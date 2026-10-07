from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from .models import Confidence, Finding, HatType, Severity

@dataclass
class DependencyInfo:

    name: str
    version: str = ""
    source_file: str = ""
    ecosystem: str = ""
    pinned: bool = False
    has_hash: bool = False

_KNOWN_VULN_PACKAGES = {
    "pyyaml": {"below": "6.0", "cve": "CVE-2020-14343", "description": "Arbitrary code execution via yaml.load()"},
    "django": {"below": "4.2", "cve": "CVE-2023-various", "description": "Multiple security fixes in 4.2+"},
    "flask": {"below": "2.3.0", "cve": "CVE-2023-30861", "description": "Session cookie vulnerability"},
    "requests": {"below": "2.31.0", "cve": "CVE-2023-32681", "description": "Potential sensitive header leak on redirect"},
    "urllib3": {"below": "2.0.7", "cve": "CVE-2023-45803", "description": "Request body not stripped on redirect"},
    "jinja2": {"below": "3.1.3", "cve": "CVE-2024-22195", "description": "XSS vulnerability in xmlattr filter"},
    "cryptography": {"below": "41.0.6", "cve": "CVE-2023-49083", "description": "NULL pointer dereference"},
    "pillow": {"below": "10.2.0", "cve": "CVE-2023-50447", "description": "Arbitrary code execution"},
    "sqlalchemy": {"below": "2.0.0", "cve": "", "description": "Legacy API has injection risks with text()"},
    "werkzeug": {"below": "3.0.1", "cve": "CVE-2023-46136", "description": "DoS via multipart parser"},
    "express": {"below": "4.19.0", "cve": "CVE-2024-29041", "description": "Open redirect vulnerability"},
    "lodash": {"below": "4.17.21", "cve": "CVE-2021-23337", "description": "Prototype pollution"},
    "axios": {"below": "1.6.0", "cve": "CVE-2023-45857", "description": "CSRF token exposure"},
    "jsonwebtoken": {"below": "9.0.0", "cve": "CVE-2022-23529", "description": "Insecure key handling"},
    "moment": {"below": "999.0.0", "cve": "", "description": "Deprecated — use date-fns or dayjs"},
    "minimist": {"below": "1.2.6", "cve": "CVE-2021-44906", "description": "Prototype pollution"},
    "qs": {"below": "6.11.0", "cve": "CVE-2022-24999", "description": "Prototype pollution"},
    "node-fetch": {"below": "3.3.2", "cve": "CVE-2022-0235", "description": "Exposure of sensitive headers"},
}

class DependencyAnalyzer:

    def __init__(self, project_path: str):
        self.project_path = os.path.abspath(project_path)
        self.dependencies: list[DependencyInfo] = []
        self.findings: list[Finding] = []

    def analyze(self) -> list[Finding]:

        self.dependencies.clear()
        self.findings.clear()

        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in {
                ".git", "node_modules", "__pycache__", "venv", ".venv"
            }]

            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.project_path)
                fname_lower = fname.lower()

                if fname_lower == "requirements.txt":
                    self._parse_requirements(fpath, rel_path)
                elif fname_lower == "package.json":
                    self._parse_package_json(fpath, rel_path)
                elif fname_lower == "pipfile":
                    self._parse_pipfile(fpath, rel_path)
                elif fname_lower == "pyproject.toml":
                    self._parse_pyproject(fpath, rel_path)

        self._check_known_vulns()

        self._check_antipatterns()

        return self.findings

    def _parse_requirements(self, fpath: str, rel_path: str):

        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue

                    match = re.match(
                        r'^([A-Za-z0-9_\-\.]+)\s*(?:([><=!~]+)\s*([0-9][A-Za-z0-9\.\-\_]*))?',
                        line,
                    )
                    if match:
                        name = match.group(1).lower()
                        version = match.group(3) or ""
                        pinned = match.group(2) == "==" if match.group(2) else False
                        has_hash = "--hash" in line

                        self.dependencies.append(DependencyInfo(
                            name=name,
                            version=version,
                            source_file=rel_path,
                            ecosystem="python-pip",
                            pinned=pinned,
                            has_hash=has_hash,
                        ))
        except (OSError, UnicodeDecodeError):
            pass

    def _parse_package_json(self, fpath: str, rel_path: str):

        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return

        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for name, ver_spec in deps.items():
                version = re.sub(r'^[\^~>=<]', '', str(ver_spec))
                self.dependencies.append(DependencyInfo(
                    name=name.lower(),
                    version=version,
                    source_file=rel_path,
                    ecosystem="npm",
                    pinned=not any(c in str(ver_spec) for c in "^~><=*x"),
                ))

    def _parse_pipfile(self, fpath: str, rel_path: str):

        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                content = fh.read()
        except (OSError, UnicodeDecodeError):
            return

        in_packages = False
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("[packages]") or line.startswith("[dev-packages]"):
                in_packages = True
                continue
            if line.startswith("["):
                in_packages = False
                continue
            if in_packages and "=" in line:
                parts = line.split("=", 1)
                name = parts[0].strip().strip('"').lower()
                version = parts[1].strip().strip('"').strip("*")
                if name:
                    self.dependencies.append(DependencyInfo(
                        name=name,
                        version=version,
                        source_file=rel_path,
                        ecosystem="python-pipenv",
                    ))

    def _parse_pyproject(self, fpath: str, rel_path: str):

        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                content = fh.read()
        except (OSError, UnicodeDecodeError):
            return

        dep_match = re.findall(
            r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL
        )
        for block in dep_match:
            for line in block.split("\n"):
                line = line.strip().strip(",").strip('"').strip("'")
                if not line:
                    continue
                match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*(?:([><=!~]+)\s*([0-9][\S]*))?', line)
                if match:
                    self.dependencies.append(DependencyInfo(
                        name=match.group(1).lower(),
                        version=match.group(3) or "",
                        source_file=rel_path,
                        ecosystem="python",
                    ))

    def _check_known_vulns(self):

        for dep in self.dependencies:
            vuln = _KNOWN_VULN_PACKAGES.get(dep.name)
            if not vuln:
                continue

            if dep.version and self._version_below(dep.version, vuln["below"]):
                self.findings.append(Finding(
                    hat=HatType.WHITE,
                    title=f"Vulnerable Dependency: {dep.name} {dep.version}",
                    description=(
                        f"{dep.name}=={dep.version} has known vulnerabilities. "
                        f"{vuln['description']}"
                    ),
                    severity=Severity.HIGH if vuln.get("cve") else Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED if dep.version else Confidence.LIKELY,
                    file=dep.source_file,
                    vulnerability_type="Vulnerable Dependency",
                    evidence=f"{dep.name}=={dep.version} (threshold: {vuln['below']})",
                    attack_scenario=f"Attacker exploits {vuln.get('cve', 'known vulnerability')} in {dep.name} to compromise the application.",
                    recommended_fix=f"Upgrade {dep.name} to version {vuln['below']} or later.",
                    cwe="CWE-1104",
                    owasp="A06:2021 – Vulnerable and Outdated Components",
                ))

    def _check_antipatterns(self):

        unpinned = [d for d in self.dependencies if not d.pinned and d.version]
        if unpinned:
            names = ", ".join(d.name for d in unpinned[:5])
            remainder = len(unpinned) - 5
            if remainder > 0:
                names += f", ... (+{remainder} more)"

            self.findings.append(Finding(
                hat=HatType.WHITE,
                title="Unpinned Dependencies",
                description=f"{len(unpinned)} dependencies are not pinned to exact versions: {names}",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                file=unpinned[0].source_file,
                vulnerability_type="Dependency Management",
                evidence=names,
                attack_scenario="Unpinned dependencies may be automatically upgraded to malicious versions (dependency confusion, typosquatting).",
                recommended_fix="Pin all dependencies to exact versions. Use lock files (package-lock.json, Pipfile.lock).",
                cwe="CWE-1104",
                owasp="A06:2021 – Vulnerable and Outdated Components",
            ))

        has_lockfile = any(
            d.source_file.endswith((".lock", "lock.json", "lock.yaml"))
            for d in self.dependencies
        )
        if self.dependencies and not has_lockfile:
            self.findings.append(Finding(
                hat=HatType.WHITE,
                title="Missing Lock File",
                description="No dependency lock file found. Builds may be non-reproducible.",
                severity=Severity.LOW,
                confidence=Confidence.POSSIBLE,
                file=self.dependencies[0].source_file if self.dependencies else "",
                vulnerability_type="Dependency Management",
                attack_scenario="Without a lock file, builds may install different versions, including potentially compromised packages.",
                recommended_fix="Generate and commit a lock file (pip freeze, npm ci, etc.).",
                cwe="CWE-1104",
                owasp="A06:2021 – Vulnerable and Outdated Components",
            ))

    @staticmethod
    def _version_below(current: str, threshold: str) -> bool:

        def to_tuple(v: str) -> tuple:
            parts = re.findall(r'\d+', v)
            return tuple(int(p) for p in parts[:3])

        try:
            return to_tuple(current) < to_tuple(threshold)
        except (ValueError, IndexError):
            return False

    @property
    def stats(self) -> dict:
        ecosystems: dict[str, int] = {}
        for d in self.dependencies:
            ecosystems[d.ecosystem] = ecosystems.get(d.ecosystem, 0) + 1

        return {
            "total_dependencies": len(self.dependencies),
            "by_ecosystem": ecosystems,
            "pinned": sum(1 for d in self.dependencies if d.pinned),
            "unpinned": sum(1 for d in self.dependencies if not d.pinned),
            "vulnerable_findings": len(self.findings),
        }
