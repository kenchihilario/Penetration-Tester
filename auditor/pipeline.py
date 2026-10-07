from __future__ import annotations
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from .auth_gate import AuthorizationScope, print_policy
from .dependency_analyzer import DependencyAnalyzer
from .discovery import AssetDiscovery
from .hats import (
    BlueHatAnalyzer,
    GrayHatAnalyzer,
    PurpleHatAnalyzer,
    RedHatAnalyzer,
)
from .models import AuditReport, Finding, HatType, Severity
from .scanner import VulnerabilityScanner

@dataclass
class PipelineStage:
    name: str
    status: str = "pending"
    start_time: float = 0.0
    end_time: float = 0.0
    items_produced: int = 0
    error: str = ""

    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def duration_str(self) -> str:
        d = self.duration
        if d < 1:
            return f"{d * 1000:.0f}ms"
        return f"{d:.1f}s"

class AuditPipeline:
    def __init__(
        self,
        project_path: str,
        scope: Optional[AuthorizationScope] = None,
        on_progress: Optional[Callable[[str, str], None]] = None,
    ):
        self.project_path = os.path.abspath(project_path)
        self.scope = scope or AuthorizationScope(
            project_path=self.project_path,
            static_analysis_only=True,
        )
        self.on_progress = on_progress or (lambda stage, msg: None)
        self.stages: list[PipelineStage] = [
            PipelineStage("Authorization Gate"),
            PipelineStage("Asset Discovery"),
            PipelineStage("Static Analysis"),
            PipelineStage("Dependency Analysis"),
            PipelineStage("White Hat Pass"),
            PipelineStage("Red Hat Pass"),
            PipelineStage("Blue Hat Pass"),
            PipelineStage("Purple Hat Pass"),
            PipelineStage("Gray Hat Pass"),
            PipelineStage("Risk Prioritization"),
            PipelineStage("Report Generation"),
        ]
        self.report = AuditReport(
            project_name=os.path.basename(self.project_path),
            project_path=self.project_path,
        )

    def run(self) -> AuditReport:
        overall_start = time.time()
        try:
            self._run_stage(0, self._auth_gate)
            self._run_stage(1, self._asset_discovery)
            self._run_stage(2, self._static_analysis)
            self._run_stage(3, self._dependency_analysis)
            self._run_stage(4, self._white_hat_pass)
            self._run_stage(5, self._red_hat_pass)
            self._run_stage(6, self._blue_hat_pass)
            self._run_stage(7, self._purple_hat_pass)
            self._run_stage(8, self._gray_hat_pass)
            self._run_stage(9, self._prioritize_risks)
            self._run_stage(10, self._generate_summary)
        except Exception as e:
            for stage in self.stages:
                if stage.status == "pending":
                    stage.status = "skipped"
            raise
        return self.report

    def _run_stage(self, idx: int, func: Callable):
        stage = self.stages[idx]
        stage.status = "running"
        stage.start_time = time.time()
        self.on_progress(stage.name, "started")
        try:
            func(stage)
            stage.status = "done"
            stage.end_time = time.time()
            self.on_progress(stage.name, f"completed ({stage.items_produced} items, {stage.duration_str})")
        except Exception as e:
            stage.status = "error"
            stage.error = str(e)
            stage.end_time = time.time()
            self.on_progress(stage.name, f"error: {e}")
            raise

    def _auth_gate(self, stage: PipelineStage):
        if not os.path.isdir(self.project_path):
            raise FileNotFoundError(f"Project path not found: {self.project_path}")
        self.on_progress("Authorization Gate", "Policy acknowledged")
        stage.items_produced = 1

    def _asset_discovery(self, stage: PipelineStage):
        discovery = AssetDiscovery(self.project_path)
        self.report.assets = discovery.scan()
        stage.items_produced = len(self.report.assets)
        self._discovery_stats = discovery.stats

    def _static_analysis(self, stage: PipelineStage):
        scanner = VulnerabilityScanner(self.project_path)
        self._static_findings = scanner.scan()
        stage.items_produced = len(self._static_findings)
        self._scanner_stats = scanner.stats

    def _dependency_analysis(self, stage: PipelineStage):
        analyzer = DependencyAnalyzer(self.project_path)
        self._dep_findings = analyzer.analyze()
        stage.items_produced = len(self._dep_findings)
        self._dep_stats = analyzer.stats

    def _white_hat_pass(self, stage: PipelineStage):
        all_findings = self._static_findings + self._dep_findings
        for f in all_findings:
            f.hat = HatType.WHITE
        self.report.findings.extend(all_findings)
        stage.items_produced = len(all_findings)

    def _red_hat_pass(self, stage: PipelineStage):
        red = RedHatAnalyzer()
        self.report.attack_paths = red.analyze(self.report.findings)
        stage.items_produced = len(self.report.attack_paths)

    def _blue_hat_pass(self, stage: PipelineStage):
        blue = BlueHatAnalyzer()
        self.report.blue_assessments = blue.analyze(
            self.report.findings,
            self.report.attack_paths,
            self.project_path,
        )
        stage.items_produced = len(self.report.blue_assessments)

    def _purple_hat_pass(self, stage: PipelineStage):
        purple = PurpleHatAnalyzer()
        self.report.purple_validations = purple.validate(
            self.report.attack_paths,
            self.report.blue_assessments,
        )
        stage.items_produced = len(self.report.purple_validations)

    def _gray_hat_pass(self, stage: PipelineStage):
        gray = GrayHatAnalyzer()
        self.report.gray_hat_notes = gray.analyze(
            self.project_path,
            self.report.findings,
        )
        stage.items_produced = len(self.report.gray_hat_notes)

    def _prioritize_risks(self, stage: PipelineStage):
        all_findings = self.report.findings + self.report.gray_hat_notes
        all_findings.sort(key=lambda f: f.risk_score, reverse=True)
        self.report.risk_matrix = {
            "total": len(all_findings),
            "by_severity": {},
            "by_hat": {},
            "top_risks": [],
        }
        for sev in Severity:
            count = sum(1 for f in all_findings if f.severity == sev)
            if count:
                self.report.risk_matrix["by_severity"][sev.value] = count
        for hat in HatType:
            count = sum(1 for f in all_findings if f.hat == hat)
            if count:
                self.report.risk_matrix["by_hat"][hat.value] = count
        self.report.risk_matrix["top_risks"] = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "score": f.risk_score,
                "file": f.file,
            }
            for f in all_findings[:10]
        ]
        stage.items_produced = len(all_findings)

    def _generate_summary(self, stage: PipelineStage):
        all_findings = self.report.findings + self.report.gray_hat_notes
        critical = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in all_findings if f.severity == Severity.LOW)
        info = sum(1 for f in all_findings if f.severity == Severity.INFO)
        summary_parts = [
            f"Multi-Hat Security Audit of '{self.report.project_name}'",
            f"Scan completed: {self.report.scan_timestamp}",
            "",
            f"Assets discovered: {len(self.report.assets)}",
            f"Total findings: {len(all_findings)}",
            f"  Critical: {critical}",
            f"  High: {high}",
            f"  Medium: {medium}",
            f"  Low: {low}",
            f"  Informational: {info}",
            "",
            f"Attack paths modeled: {len(self.report.attack_paths)}",
            f"Blue team assessments: {len(self.report.blue_assessments)}",
            f"Purple validations: {len(self.report.purple_validations)}",
            f"Gray hat findings: {len(self.report.gray_hat_notes)}",
        ]
        if critical > 0:
            summary_parts.extend([
                "",
                "CRITICAL FINDINGS REQUIRE IMMEDIATE ATTENTION",
            ])
        self.report.executive_summary = "\n".join(summary_parts)
        stage.items_produced = 1

    @property
    def pipeline_stats(self) -> dict:
        return {
            "stages": [
                {
                    "name": s.name,
                    "status": s.status,
                    "duration": s.duration_str,
                    "items": s.items_produced,
                }
                for s in self.stages
            ],
            "total_duration": f"{sum(s.duration for s in self.stages):.1f}s",
        }
