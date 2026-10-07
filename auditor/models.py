from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"

    @property
    def label(self) -> str:
        return f"[{self.name}]"

    @property
    def numeric(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

class Confidence(Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    FALSE_POSITIVE = "FALSE POSITIVE"

    @property
    def numeric(self) -> int:
        return {
            Confidence.CONFIRMED: 4,
            Confidence.LIKELY: 3,
            Confidence.POSSIBLE: 2,
            Confidence.FALSE_POSITIVE: 1,
        }[self]

class HatType(Enum):
    WHITE = "white"
    RED = "red"
    BLUE = "blue"
    PURPLE = "purple"
    GRAY = "gray"
    CODE = "code-review"

    @property
    def label(self) -> str:
        return {
            HatType.WHITE: "White Hat - Penetration Tester",
            HatType.RED: "Red Hat - Adversarial Attacker",
            HatType.BLUE: "Blue Hat - Defender / SOC Analyst",
            HatType.PURPLE: "Purple Hat - Red+Blue Validation",
            HatType.GRAY: "Gray Hat - Edge-Case Researcher",
            HatType.CODE: "Secure Code Reviewer",
        }[self]

    @property
    def short_label(self) -> str:
        return {
            HatType.WHITE: "WHITE",
            HatType.RED: "RED",
            HatType.BLUE: "BLUE",
            HatType.PURPLE: "PURPLE",
            HatType.GRAY: "GRAY",
            HatType.CODE: "CODE",
        }[self]

class AssetType(Enum):
    WEB_APP = "web_application"
    API = "api"
    DATABASE = "database"
    AUTH_SYSTEM = "authentication_system"
    CONFIG = "configuration_file"
    DEPENDENCY = "dependency"
    NETWORK_SVC = "network_service"
    STATIC_FILE = "static_file"
    DOCKER = "docker/container"
    SECRET = "secret/credential"
    SOURCE_CODE = "source_code"

@dataclass
class Asset:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    asset_type: AssetType = AssetType.SOURCE_CODE
    path: str = ""
    details: dict = field(default_factory=dict)
    risk_notes: list[str] = field(default_factory=list)

@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    hat: HatType = HatType.WHITE
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.POSSIBLE
    file: str = ""
    line: Optional[int] = None
    function: str = ""
    vulnerability_type: str = ""
    evidence: str = ""
    attack_scenario: str = ""
    recommended_fix: str = ""
    cwe: str = ""
    owasp: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def risk_score(self) -> int:
        return self.severity.numeric * self.confidence.numeric

@dataclass
class AttackStep:
    order: int = 0
    description: str = ""
    technique: str = ""
    access_required: str = ""
    finding_id: str = ""

@dataclass
class AttackPath:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    objective: str = ""
    steps: list[AttackStep] = field(default_factory=list)
    required_access: str = ""
    vulnerabilities: list[str] = field(default_factory=list)
    expected_impact: str = ""
    detection_opportunities: list[str] = field(default_factory=list)
    recommended_mitigation: list[str] = field(default_factory=list)
    severity: Severity = Severity.HIGH
    likelihood: str = "MEDIUM"

@dataclass
class DefensiveControl:
    control_name: str = ""
    present: bool = False
    effective: bool = False
    notes: str = ""

@dataclass
class BlueTeamAssessment:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    related_finding_id: str = ""
    related_attack_path_id: str = ""
    logs_available: bool = False
    log_details: str = ""
    detection_possible: bool = False
    detection_details: str = ""
    alerts_configured: bool = False
    alert_details: str = ""
    ioc_indicators: list[str] = field(default_factory=list)
    investigation_targets: list[str] = field(default_factory=list)
    missing_controls: list[DefensiveControl] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

class ValidationResult(Enum):
    ATTACK_BLOCKED = "ATTACK_BLOCKED"
    ATTACK_DETECTED = "ATTACK_DETECTED"
    ATTACK_UNDETECTED = "ATTACK_UNDETECTED"
    CONTROL_MISSING = "CONTROL_MISSING"
    NOT_TESTED = "NOT_TESTED"

@dataclass
class PurpleValidation:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    attack_path_id: str = ""
    finding_id: str = ""
    blue_assessment_id: str = ""
    result: ValidationResult = ValidationResult.NOT_TESTED
    red_summary: str = ""
    blue_summary: str = ""
    gap_analysis: str = ""
    retest_needed: bool = False
    retest_result: str = ""

@dataclass
class AuditReport:
    project_name: str = ""
    project_path: str = ""
    scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    blue_assessments: list[BlueTeamAssessment] = field(default_factory=list)
    purple_validations: list[PurpleValidation] = field(default_factory=list)
    gray_hat_notes: list[Finding] = field(default_factory=list)
    executive_summary: str = ""
    risk_matrix: dict = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return len(self.findings) + len(self.gray_hat_notes)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings + self.gray_hat_notes:
            result[f.severity].append(f)
        return result

    def findings_by_hat(self) -> dict[HatType, list[Finding]]:
        result: dict[HatType, list[Finding]] = {h: [] for h in HatType}
        for f in self.findings + self.gray_hat_notes:
            result[f.hat].append(f)
        return result
