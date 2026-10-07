from __future__ import annotations
import json
import os
from datetime import datetime
from typing import Optional
from .models import (
    AuditReport, AttackPath, BlueTeamAssessment, Finding,
    HatType, PurpleValidation, Severity, ValidationResult,
)

class ReportGenerator:
    def __init__(self, report: AuditReport):
        self.report = report

    def generate_html(self, output_path: Optional[str] = None) -> str:
        all_findings = self.report.findings + self.report.gray_hat_notes
        all_findings.sort(key=lambda f: f.risk_score, reverse=True)
        sev_counts = {s: 0 for s in Severity}
        for f in all_findings:
            sev_counts[f.severity] += 1
        hat_counts = {h: 0 for h in HatType}
        for f in all_findings:
            hat_counts[f.hat] += 1
        html = self._build_html(all_findings, sev_counts, hat_counts)
        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(html)
        return html

    def generate_json(self, output_path: Optional[str] = None) -> str:
        all_findings = self.report.findings + self.report.gray_hat_notes
        data = {
            "meta": {
                "project_name": self.report.project_name,
                "project_path": self.report.project_path,
                "scan_timestamp": self.report.scan_timestamp,
                "total_findings": len(all_findings),
                "critical_count": self.report.critical_count,
                "high_count": self.report.high_count,
            },
            "executive_summary": self.report.executive_summary,
            "risk_matrix": self.report.risk_matrix,
            "assets": [
                {
                    "id": a.id,
                    "name": a.name,
                    "type": a.asset_type.value,
                    "path": a.path,
                    "details": a.details,
                    "risk_notes": a.risk_notes,
                }
                for a in self.report.assets
            ],
            "findings": [
                {
                    "id": f.id,
                    "hat": f.hat.value,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "risk_score": f.risk_score,
                    "file": f.file,
                    "line": f.line,
                    "function": f.function,
                    "vulnerability_type": f.vulnerability_type,
                    "evidence": f.evidence,
                    "attack_scenario": f.attack_scenario,
                    "recommended_fix": f.recommended_fix,
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                }
                for f in all_findings
            ],
            "attack_paths": [
                {
                    "id": ap.id,
                    "objective": ap.objective,
                    "steps": [
                        {
                            "order": s.order,
                            "description": s.description,
                            "technique": s.technique,
                            "access_required": s.access_required,
                        }
                        for s in ap.steps
                    ],
                    "expected_impact": ap.expected_impact,
                    "severity": ap.severity.value,
                    "likelihood": ap.likelihood,
                    "detection_opportunities": ap.detection_opportunities,
                    "recommended_mitigation": ap.recommended_mitigation,
                }
                for ap in self.report.attack_paths
            ],
            "blue_assessments": [
                {
                    "id": ba.id,
                    "related_attack_path_id": ba.related_attack_path_id,
                    "logs_available": ba.logs_available,
                    "detection_possible": ba.detection_possible,
                    "alerts_configured": ba.alerts_configured,
                    "ioc_indicators": ba.ioc_indicators,
                    "missing_controls": [
                        {"name": c.control_name, "present": c.present, "notes": c.notes}
                        for c in ba.missing_controls
                    ],
                    "recommendations": ba.recommendations,
                }
                for ba in self.report.blue_assessments
            ],
            "purple_validations": [
                {
                    "id": pv.id,
                    "attack_path_id": pv.attack_path_id,
                    "result": pv.result.value,
                    "red_summary": pv.red_summary,
                    "blue_summary": pv.blue_summary,
                    "gap_analysis": pv.gap_analysis,
                    "retest_needed": pv.retest_needed,
                }
                for pv in self.report.purple_validations
            ],
        }
        output = json.dumps(data, indent=2, ensure_ascii=False)
        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(output)
        return output

    def _build_html(self, all_findings, sev_counts, hat_counts) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Hat Security Audit - {self._esc(self.report.project_name)}</title>
    <style>{self._get_css()}</style>
</head>
<body>
    <div class="app">
        {self._build_header()}
        {self._build_summary_cards(sev_counts)}
        {self._build_pipeline_status()}
        {self._build_findings_section(all_findings)}
        {self._build_attack_paths_section()}
        {self._build_blue_team_section()}
        {self._build_purple_section()}
        {self._build_gray_hat_section()}
        {self._build_assets_section()}
        {self._build_footer()}
    </div>
    <script>{self._get_js()}</script>
</body>
</html>"""

    def _build_header(self) -> str:
        return f"""
    <header class="hero">
        <div class="hero-content">
            <h1 class="hero-title">Multi-Hat Security Auditor</h1>
            <p class="hero-subtitle">Project: {self._esc(self.report.project_name)}</p>
            <div class="hero-meta">
                <span class="meta-item">Path: {self._esc(self.report.project_path)}</span>
                <span class="meta-item">Time: {self._format_timestamp(self.report.scan_timestamp)}</span>
            </div>
        </div>
    </header>"""

    def _build_summary_cards(self, sev_counts) -> str:
        total = sum(sev_counts.values())
        cards = [
            ("Total Findings", str(total), "total"),
            ("Critical", str(sev_counts.get(Severity.CRITICAL, 0)), "critical"),
            ("High", str(sev_counts.get(Severity.HIGH, 0)), "high"),
            ("Medium", str(sev_counts.get(Severity.MEDIUM, 0)), "medium"),
            ("Low", str(sev_counts.get(Severity.LOW, 0)), "low"),
            ("Info", str(sev_counts.get(Severity.INFO, 0)), "info"),
            ("Attack Paths", str(len(self.report.attack_paths)), "attacks"),
            ("Assets", str(len(self.report.assets)), "assets"),
        ]
        cards_html = "\\n".join(
            f'''<div class="stat-card {cls}">
                <div class="stat-value">{val}</div>
                <div class="stat-label">{label}</div>
            </div>'''
            for label, val, cls in cards
        )
        return f"""
    <section class="summary-section">
        <div class="stats-grid">{cards_html}</div>
    </section>"""

    def _build_pipeline_status(self) -> str:
        stages = [
            "Authorization Gate", "Asset Discovery", "Static Analysis",
            "Dependency Analysis", "White Hat Pass", "Red Hat Pass",
            "Blue Hat Pass", "Purple Hat Pass", "Gray Hat Pass",
            "Risk Prioritization", "Report Generation"
        ]
        items = "\\n".join(
            f'''<div class="pipeline-step done">
                <div class="step-indicator">
                    <span class="step-check">DONE</span>
                </div>
                <span class="step-name">{name}</span>
            </div>'''
            for name in stages
        )
        return f"""
    <section class="section pipeline-section">
        <h2 class="section-title">Audit Pipeline</h2>
        <div class="pipeline-track">{items}</div>
    </section>"""

    def _build_findings_section(self, all_findings) -> str:
        if not all_findings:
            return """
    <section class="section">
        <h2 class="section-title">No Findings</h2>
        <p class="no-data">No vulnerabilities detected.</p>
    </section>"""
        finding_cards = "\\n".join(
            self._finding_card(f, i) for i, f in enumerate(all_findings)
        )
        return f"""
    <section class="section" id="findings">
        <h2 class="section-title">Findings</h2>
        <div class="filter-bar">
            <button class="filter-btn active" data-filter="all">All</button>
            <button class="filter-btn" data-filter="critical">Critical</button>
            <button class="filter-btn" data-filter="high">High</button>
            <button class="filter-btn" data-filter="medium">Medium</button>
            <button class="filter-btn" data-filter="low">Low</button>
            <button class="filter-btn" data-filter="informational">Info</button>
        </div>
        <div class="findings-list">{finding_cards}</div>
    </section>"""

    def _finding_card(self, f: Finding, idx: int) -> str:
        sev_class = f.severity.value
        confidence_class = f.confidence.value.lower().replace(" ", "-")
        code_section = ""
        if f.evidence:
            code_section = f"""
            <div class="finding-evidence">
                <span class="evidence-label">Evidence:</span>
                <code class="evidence-code">{self._esc(f.evidence)}</code>
            </div>"""
        location = ""
        if f.file:
            loc_parts = [f.file]
            if f.line:
                loc_parts.append(f"Line {f.line}")
            if f.function:
                loc_parts.append(f"Function: {f.function}")
            location = f"""<div class="finding-location">Location: {self._esc(' -> '.join(loc_parts))}</div>"""
        return f"""
        <div class="finding-card {sev_class}" data-severity="{f.severity.value}">
            <div class="finding-header" onclick="this.closest('.finding-card').classList.toggle('expanded')">
                <div class="finding-badges">
                    <span class="severity-badge {sev_class}">[{f.severity.value.upper()}]</span>
                    <span class="confidence-badge {confidence_class}">Conf: {f.confidence.value}</span>
                    <span class="hat-indicator">Hat: {f.hat.short_label if f.hat else 'WHITE'}</span>
                    <span class="risk-score">Risk: {f.risk_score}</span>
                </div>
                <h3 class="finding-title">{self._esc(f.title)}</h3>
                {location}
                <span class="expand-arrow">Expand</span>
            </div>
            <div class="finding-body">
                <div class="finding-description">
                    <h4>Description</h4>
                    <p>{self._esc(f.description)}</p>
                </div>
                {code_section}
                <div class="finding-detail-grid">
                    <div class="detail-block attack">
                        <h4>Attack Scenario</h4>
                        <p>{self._esc(f.attack_scenario)}</p>
                    </div>
                    <div class="detail-block fix">
                        <h4>Recommended Fix</h4>
                        <p>{self._esc(f.recommended_fix)}</p>
                    </div>
                </div>
                <div class="finding-refs">
                    {f'<span class="ref-tag">{self._esc(f.cwe)}</span>' if f.cwe else ''}
                    {f'<span class="ref-tag">{self._esc(f.owasp)}</span>' if f.owasp else ''}
                    {f'<span class="ref-tag vuln-type">{self._esc(f.vulnerability_type)}</span>' if f.vulnerability_type else ''}
                </div>
            </div>
        </div>"""

    def _build_attack_paths_section(self) -> str:
        if not self.report.attack_paths:
            return ""
        paths_html = "\\n".join(
            self._attack_path_card(ap, i)
            for i, ap in enumerate(self.report.attack_paths)
        )
        return f"""
    <section class="section" id="attack-paths">
        <h2 class="section-title">Red Hat - Attack Path Modeling</h2>
        <div class="attack-paths-list">{paths_html}</div>
    </section>"""

    def _attack_path_card(self, ap: AttackPath, idx: int) -> str:
        steps_html = "\\n".join(
            f'''<div class="attack-step">
                <div class="step-number">{s.order}</div>
                <div class="step-content">
                    <div class="step-desc">{self._esc(s.description)}</div>
                    <div class="step-meta">Access: {self._esc(s.access_required)}</div>
                </div>
            </div>'''
            for s in ap.steps
        )
        detection_html = "\\n".join(
            f'<li>{self._esc(d)}</li>' for d in ap.detection_opportunities
        )
        return f"""
        <div class="attack-path-card">
            <div class="path-header" onclick="this.closest('.attack-path-card').classList.toggle('expanded')">
                <div class="path-badges">
                    <span class="severity-badge {ap.severity.value}">[{ap.severity.value.upper()}]</span>
                    <span class="likelihood-badge">Likelihood: {ap.likelihood}</span>
                </div>
                <h3 class="path-objective">Objective: {self._esc(ap.objective)}</h3>
                <span class="expand-arrow">Expand</span>
            </div>
            <div class="path-body">
                <div class="attack-chain">
                    <h4>Attack Chain</h4>
                    <div class="chain-steps">{steps_html}</div>
                </div>
                <div class="path-impact">
                    <h4>Expected Impact</h4>
                    <p>{self._esc(ap.expected_impact)}</p>
                </div>
                <div class="path-detection">
                    <h4>Detection Opportunities</h4>
                    <ul>{detection_html}</ul>
                </div>
            </div>
        </div>"""

    def _build_blue_team_section(self) -> str:
        if not self.report.blue_assessments:
            return ""
        assessments_html = "\\n".join(
            self._blue_assessment_card(ba, i)
            for i, ba in enumerate(self.report.blue_assessments)
        )
        return f"""
    <section class="section" id="blue-team">
        <h2 class="section-title">Blue Hat - Defensive Assessment</h2>
        <div class="blue-list">{assessments_html}</div>
    </section>"""

    def _blue_assessment_card(self, ba: BlueTeamAssessment, idx: int) -> str:
        status_items = [
            ("Authentication Logs Available", ba.logs_available),
            ("Detection Possible", ba.detection_possible),
            ("Alerts Configured", ba.alerts_configured),
        ]
        status_html = "\\n".join(
            f'''<div class="defense-status {'active' if active else 'inactive'}">
                <span class="status-label">{label}</span>
                <span class="status-value">{'YES' if active else 'NO'}</span>
            </div>'''
            for label, active in status_items
        )
        missing_html = "\\n".join(
            f'''<div class="missing-control">
                <span class="control-name">- {self._esc(c.control_name)}</span>
            </div>'''
            for c in ba.missing_controls
        )
        ioc_html = "\\n".join(f'<li>{self._esc(ioc)}</li>' for ioc in ba.ioc_indicators)
        recs_html = "\\n".join(f'<li>{self._esc(r)}</li>' for r in ba.recommendations)
        return f"""
        <div class="blue-card">
            <div class="blue-header" onclick="this.closest('.blue-card').classList.toggle('expanded')">
                <h3>Defensive Analysis</h3>
                <div class="defense-summary">
                    <span class="defense-stat">Detection: {'Possible' if ba.detection_possible else 'Gap'}</span>
                    <span class="defense-stat">Missing Controls: {len(ba.missing_controls)}</span>
                </div>
                <span class="expand-arrow">Expand</span>
            </div>
            <div class="blue-body">
                <div class="defense-grid">
                    <div class="defense-block">
                        <h4>Defense Status</h4>
                        {status_html}
                    </div>
                    <div class="defense-block">
                        <h4>Missing Controls</h4>
                        {missing_html if missing_html else '<p class="all-good">All basic controls present</p>'}
                    </div>
                </div>
                <div class="defense-block">
                    <h4>Indicators of Compromise</h4>
                    <ul class="ioc-list">{ioc_html}</ul>
                </div>
                <div class="defense-block">
                    <h4>Recommendations</h4>
                    <ul class="rec-list">{recs_html}</ul>
                </div>
            </div>
        </div>"""

    def _build_purple_section(self) -> str:
        if not self.report.purple_validations:
            return ""
        validations_html = "\\n".join(
            self._purple_card(pv, i)
            for i, pv in enumerate(self.report.purple_validations)
        )
        return f"""
    <section class="section" id="purple">
        <h2 class="section-title">Purple Hat - Red + Blue Validation</h2>
        <div class="purple-list">{validations_html}</div>
    </section>"""

    def _purple_card(self, pv: PurpleValidation, idx: int) -> str:
        result_class = {
            ValidationResult.ATTACK_BLOCKED: "blocked",
            ValidationResult.ATTACK_DETECTED: "detected",
            ValidationResult.ATTACK_UNDETECTED: "undetected",
            ValidationResult.CONTROL_MISSING: "missing",
            ValidationResult.NOT_TESTED: "untested",
        }.get(pv.result, "untested")
        return f"""
        <div class="purple-card {result_class}">
            <div class="purple-header" onclick="this.closest('.purple-card').classList.toggle('expanded')">
                <div class="validation-result">
                    <span class="result-text">{pv.result.value.replace('_', ' ')}</span>
                </div>
                <span class="retest-badge">
                    {'RETEST NEEDED' if pv.retest_needed else 'VALIDATED'}
                </span>
                <span class="expand-arrow">Expand</span>
            </div>
            <div class="purple-body">
                <div class="purple-grid">
                    <div class="purple-block red-side">
                        <h4>Red Team Assessment</h4>
                        <pre>{self._esc(pv.red_summary)}</pre>
                    </div>
                    <div class="purple-block blue-side">
                        <h4>Blue Team Assessment</h4>
                        <pre>{self._esc(pv.blue_summary)}</pre>
                    </div>
                </div>
                <div class="gap-analysis">
                    <h4>Gap Analysis</h4>
                    <p>{self._esc(pv.gap_analysis)}</p>
                </div>
            </div>
        </div>"""

    def _build_gray_hat_section(self) -> str:
        if not self.report.gray_hat_notes:
            return ""
        findings_html = "\\n".join(
            self._finding_card(f, i) for i, f in enumerate(self.report.gray_hat_notes)
        )
        return f"""
    <section class="section" id="gray-hat">
        <h2 class="section-title">Gray Hat - Edge-Case Research</h2>
        <div class="findings-list">{findings_html}</div>
    </section>"""

    def _build_assets_section(self) -> str:
        if not self.report.assets:
            return ""
        by_type: dict[str, list] = {}
        for a in self.report.assets:
            key = a.asset_type.value
            by_type.setdefault(key, []).append(a)
        groups_html = ""
        for atype, assets in sorted(by_type.items()):
            items_html = "\\n".join(
                f'''<div class="asset-item {'has-risk' if a.risk_notes else ''}">
                    <span class="asset-path">{self._esc(a.path)}</span>
                    <span class="asset-name">{self._esc(a.name)}</span>
                    {f'<span class="asset-risk">Risk: {self._esc(a.risk_notes[0])}</span>' if a.risk_notes else ''}
                </div>'''
                for a in assets[:20]
            )
            overflow = len(assets) - 20
            if overflow > 0:
                items_html += f'<div class="asset-overflow">... and {overflow} more</div>'
            groups_html += f"""
            <div class="asset-group">
                <h3 class="asset-type-title">{atype.replace('_', ' ').title()} ({len(assets)})</h3>
                {items_html}
            </div>"""
        return f"""
    <section class="section" id="assets">
        <h2 class="section-title">Discovered Assets</h2>
        <div class="assets-grid">{groups_html}</div>
    </section>"""

    def _build_footer(self) -> str:
        return f"""
    <footer class="report-footer">
        <div class="footer-content">
            <div class="policy-box">
                <h3>Security Testing Policy</h3>
                <ol class="policy-list">
                    <li>Determine the target.</li>
                    <li>Determine whether the target is explicitly authorized.</li>
                    <li>Prefer localhost, test containers, dev/staging servers.</li>
                    <li>Never attack arbitrary external systems.</li>
                    <li>Never steal, dump, or publish credentials.</li>
                    <li>Never destroy or corrupt data.</li>
                    <li>Never establish persistence.</li>
                    <li>Never evade security monitoring.</li>
                    <li>Never use findings to attack unrelated systems.</li>
                    <li>Stop when testing could affect systems outside scope.</li>
                </ol>
            </div>
            <p class="footer-credit">
                Multi-Hat Security Auditor v1.0 - Generated {self._format_timestamp(self.report.scan_timestamp)}
            </p>
        </div>
    </footer>"""

    @staticmethod
    def _esc(text: str) -> str:
        if not text:
            return ""
        return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;")
                .replace("'", "&#39;"))

    @staticmethod
    def _format_timestamp(ts: str) -> str:
        try:
            dt = datetime.fromisoformat(ts)
            return dt.strftime("%B %d, %Y at %I:%M %p")
        except (ValueError, TypeError):
            return ts

    @staticmethod
    def _get_css() -> str:
        return """
:root {
    --bg-primary: #ffffff;
    --bg-card: #f8f9fa;
    --text-primary: #212529;
    --text-secondary: #495057;
    --border: #dee2e6;
    --accent: #0d6efd;
    --sev-critical: #dc3545;
    --sev-high: #fd7e14;
    --sev-medium: #ffc107;
    --sev-low: #0dcaf0;
    --sev-info: #6c757d;
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--font); background: var(--bg-primary); color: var(--text-primary); line-height: 1.5; padding: 20px; }
.app { max-width: 1000px; margin: 0 auto; }
.hero { padding: 40px 0; border-bottom: 2px solid var(--border); margin-bottom: 30px; }
.hero-title { font-size: 2rem; font-weight: bold; margin-bottom: 10px; }
.hero-subtitle { font-size: 1.2rem; color: var(--text-secondary); margin-bottom: 10px; }
.hero-meta { display: flex; gap: 20px; margin-bottom: 20px; color: var(--text-secondary); font-size: 0.9rem; }
.hat-badges { display: flex; gap: 10px; flex-wrap: wrap; }
.hat-badge { padding: 4px 8px; border: 1px solid var(--border); border-radius: 4px; font-size: 0.8rem; background: var(--bg-card); }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin-bottom: 30px; }
.stat-card { padding: 15px; border: 1px solid var(--border); text-align: center; border-radius: 4px; }
.stat-value { font-size: 1.5rem; font-weight: bold; margin-bottom: 5px; }
.stat-label { font-size: 0.8rem; color: var(--text-secondary); }
.section { margin-bottom: 40px; }
.section-title { font-size: 1.5rem; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
.pipeline-track { display: flex; gap: 10px; flex-wrap: wrap; }
.pipeline-step { padding: 5px 10px; border: 1px solid var(--border); border-radius: 4px; font-size: 0.8rem; background: var(--bg-card); }
.filter-bar { display: flex; gap: 10px; margin-bottom: 20px; }
.filter-btn { padding: 5px 15px; border: 1px solid var(--border); background: var(--bg-primary); cursor: pointer; }
.filter-btn.active { background: var(--border); }
.findings-list, .attack-paths-list, .blue-list, .purple-list { display: flex; flex-direction: column; gap: 15px; }
.finding-card, .attack-path-card, .blue-card, .purple-card { border: 1px solid var(--border); border-radius: 4px; }
.finding-card.critical { border-left: 4px solid var(--sev-critical); }
.finding-card.high { border-left: 4px solid var(--sev-high); }
.finding-card.medium { border-left: 4px solid var(--sev-medium); }
.finding-card.low { border-left: 4px solid var(--sev-low); }
.finding-card.informational { border-left: 4px solid var(--sev-info); }
.finding-header, .path-header, .blue-header, .purple-header { padding: 15px; cursor: pointer; background: var(--bg-card); display: flex; flex-direction: column; position: relative; }
.finding-badges, .path-badges { display: flex; gap: 10px; margin-bottom: 10px; font-size: 0.8rem; }
.severity-badge { font-weight: bold; }
.severity-badge.critical { color: var(--sev-critical); }
.severity-badge.high { color: var(--sev-high); }
.severity-badge.medium { color: var(--sev-medium); }
.severity-badge.low { color: var(--sev-low); }
.severity-badge.informational { color: var(--sev-info); }
.finding-title, .path-objective { font-size: 1.1rem; font-weight: bold; margin-bottom: 5px; }
.expand-arrow { position: absolute; right: 15px; top: 15px; font-size: 0.8rem; color: var(--accent); }
.finding-body, .path-body, .blue-body, .purple-body { display: none; padding: 15px; border-top: 1px solid var(--border); }
.finding-card.expanded .finding-body, .attack-path-card.expanded .path-body, .blue-card.expanded .blue-body, .purple-card.expanded .purple-body { display: block; }
h4 { font-size: 0.9rem; margin-bottom: 5px; margin-top: 15px; }
h4:first-child { margin-top: 0; }
pre, code { font-family: monospace; background: #f4f4f4; padding: 2px 4px; border-radius: 3px; font-size: 0.9rem; }
pre { padding: 10px; overflow-x: auto; }
.finding-detail-grid, .defense-grid, .purple-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 15px; }
.detail-block, .defense-block, .purple-block { background: var(--bg-card); padding: 10px; border: 1px solid var(--border); border-radius: 4px; }
ul { padding-left: 20px; }
.assets-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }
.asset-group { border: 1px solid var(--border); padding: 15px; border-radius: 4px; }
.asset-item { font-size: 0.85rem; padding: 5px 0; border-bottom: 1px solid var(--border); }
.report-footer { margin-top: 40px; padding-top: 20px; border-top: 2px solid var(--border); }
.policy-box { background: var(--bg-card); padding: 20px; border: 1px solid var(--border); margin-bottom: 20px; }
.footer-credit { text-align: center; font-size: 0.8rem; color: var(--text-secondary); }
        """

    @staticmethod
    def _get_js() -> str:
        return """
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const filter = btn.dataset.filter;
        document.querySelectorAll('.finding-card').forEach(card => {
            if (filter === 'all' || card.dataset.severity === filter) {
                card.style.display = '';
            } else {
                card.style.display = 'none';
            }
        });
    });
});
        """
