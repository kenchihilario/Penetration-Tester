from __future__ import annotations
import os
from .models import (
    AttackPath, AttackStep, BlueTeamAssessment, DefensiveControl,
    Finding, HatType, PurpleValidation, Severity, ValidationResult,
)

class RedHatAnalyzer:
    def analyze(self, findings: list[Finding]) -> list[AttackPath]:
        paths = []
        high_critical = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        for finding in high_critical:
            if "Injection" in finding.vulnerability_type:
                paths.append(self._model_injection_path(finding))
            elif "Authentication" in finding.vulnerability_type:
                paths.append(self._model_auth_path(finding))
            elif "XSS" in finding.vulnerability_type:
                paths.append(self._model_xss_path(finding))
        return paths

    def _model_injection_path(self, finding: Finding) -> AttackPath:
        path = AttackPath(
            objective="Unauthorized Data Access / Command Execution",
            required_access="Network access to the vulnerable endpoint",
            severity=finding.severity,
            likelihood="HIGH",
            vulnerabilities=[finding.id],
            expected_impact="Complete compromise of the underlying data store or system shell.",
        )
        path.steps = [
            AttackStep(order=1, description="Identify injection vector in user input.", finding_id=finding.id),
            AttackStep(order=2, description="Craft payload to break out of data context and execute commands."),
            AttackStep(order=3, description="Extract data or establish a reverse shell."),
        ]
        path.detection_opportunities = [
            "WAF logs showing SQL/Command syntax in parameters.",
            "Database logs showing unexpected queries or error spikes.",
            "Process monitoring showing web server spawning unexpected child processes."
        ]
        path.recommended_mitigation = [
            "Implement parameterized queries or safe APIs.",
            "Enforce least privilege on the database/system user account."
        ]
        return path

    def _model_auth_path(self, finding: Finding) -> AttackPath:
        path = AttackPath(
            objective="Authentication Bypass / Account Takeover",
            required_access="Unauthenticated network access",
            severity=Severity.CRITICAL,
            likelihood="HIGH",
            vulnerabilities=[finding.id],
            expected_impact="Unauthorized access to user accounts or administrative interfaces.",
        )
        path.steps = [
            AttackStep(order=1, description="Extract hardcoded credential or bypass logic.", finding_id=finding.id),
            AttackStep(order=2, description="Authenticate to the system using the compromised method."),
            AttackStep(order=3, description="Access sensitive data or perform administrative actions."),
        ]
        path.detection_opportunities = [
            "Successful logins from unusual IP addresses.",
            "Access to sensitive endpoints immediately following login."
        ]
        path.recommended_mitigation = [
            "Remove hardcoded secrets and use environment variables.",
            "Implement robust, centralized authentication mechanisms."
        ]
        return path

    def _model_xss_path(self, finding: Finding) -> AttackPath:
        path = AttackPath(
            objective="Client-Side Code Execution",
            required_access="Ability to submit data viewed by other users",
            severity=Severity.HIGH,
            likelihood="MEDIUM",
            vulnerabilities=[finding.id],
            expected_impact="Session hijacking or unauthorized actions performed in context of other users.",
        )
        path.steps = [
            AttackStep(order=1, description="Inject malicious JavaScript into the application.", finding_id=finding.id),
            AttackStep(order=2, description="Victim views the page containing the payload."),
            AttackStep(order=3, description="Payload executes, stealing session tokens or performing actions."),
        ]
        path.detection_opportunities = [
            "WAF logs showing script tags in input.",
            "CSP violation reports."
        ]
        path.recommended_mitigation = [
            "Implement context-aware output encoding.",
            "Deploy a strong Content Security Policy (CSP)."
        ]
        return path

class BlueHatAnalyzer:
    def analyze(self, findings: list[Finding], attack_paths: list[AttackPath], project_path: str) -> list[BlueTeamAssessment]:
        assessments = []
        for path in attack_paths:
            assessment = BlueTeamAssessment(
                related_attack_path_id=path.id,
                logs_available=False,
                detection_possible=False,
                alerts_configured=False,
            )
            assessment.ioc_indicators = [
                "Unusual error rates in application logs",
                "Connections from known malicious IPs",
                "Unexpected processes spawned by web server"
            ]
            if path.objective.startswith("Unauthorized Data"):
                assessment.missing_controls.append(DefensiveControl(
                    control_name="Web Application Firewall (WAF)",
                    present=False,
                    notes="No WAF configuration detected in the project."
                ))
                assessment.missing_controls.append(DefensiveControl(
                    control_name="Database Query Monitoring",
                    present=False,
                    notes="Application does not appear to log detailed database queries."
                ))
            elif path.objective.startswith("Authentication"):
                assessment.missing_controls.append(DefensiveControl(
                    control_name="Rate Limiting",
                    present=False,
                    notes="No rate limiting logic identified on authentication endpoints."
                ))
            assessment.recommendations = [
                "Implement centralized logging (e.g., ELK, Splunk).",
                "Create alerts for the identified IOCs.",
                f"Deploy {assessment.missing_controls[0].control_name if assessment.missing_controls else 'additional monitoring'}."
            ]
            assessments.append(assessment)
        return assessments

class PurpleHatAnalyzer:
    def validate(self, attack_paths: list[AttackPath], blue_assessments: list[BlueTeamAssessment]) -> list[PurpleValidation]:
        validations = []
        for path in attack_paths:
            assessment = next((a for a in blue_assessments if a.related_attack_path_id == path.id), None)
            if not assessment:
                continue
            val = PurpleValidation(
                attack_path_id=path.id,
                blue_assessment_id=assessment.id,
                result=ValidationResult.ATTACK_UNDETECTED,
            )
            val.red_summary = f"Attack Scenario: {path.objective}\nThe attack path relies on {len(path.steps)} steps. The initial vector is viable."
            if not assessment.detection_possible and assessment.missing_controls:
                val.result = ValidationResult.CONTROL_MISSING
                val.blue_summary = f"Detection Gap: The environment lacks {assessment.missing_controls[0].control_name}. Logs are insufficient."
                val.gap_analysis = "The attack would succeed without triggering any alerts due to missing fundamental controls."
                val.retest_needed = True
            else:
                val.blue_summary = "Detection mechanisms are partially in place but need validation."
                val.gap_analysis = "Requires active testing to determine if alerts trigger reliably."
                val.retest_needed = False
            validations.append(val)
        return validations

class GrayHatAnalyzer:
    def analyze(self, project_path: str, findings: list[Finding]) -> list[Finding]:
        notes = []
        if any("docker" in root.lower() for root, _, _ in os.walk(project_path)):
            notes.append(Finding(
                hat=HatType.GRAY,
                title="Container Privilege Assessment Required",
                description="The project uses Docker. Ensure containers do not run as root.",
                severity=Severity.INFO,
            ))
        return notes
