from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

from .models import (
    AssetType, Confidence, Finding, HatType, Severity,
)

@dataclass
class VulnRule:
    id: str
    name: str
    vulnerability_type: str
    pattern: str
    severity: Severity
    confidence: Confidence
    description: str
    attack_scenario: str
    recommended_fix: str
    cwe: str = ""
    owasp: str = ""
    file_extensions: tuple[str, ...] = ()
    negative_patterns: tuple[str, ...] = ()

VULN_RULES: list[VulnRule] = [
    VulnRule(
        id="SQLI-001",
        name="SQL Injection - String Concatenation",
        vulnerability_type="SQL Injection",
        pattern=r'(?i)(execute|cursor\.execute|query|raw_query|rawQuery|\.query)\s*\(\s*[f\"''].*\{.*\}|%s|'' \+ |\" \+ |\$\{',
        severity=Severity.CRITICAL,
        confidence=Confidence.LIKELY,
        description="User input appears to be concatenated directly into SQL queries.",
        attack_scenario="An attacker can inject SQL commands to read, modify, or delete database data, or execute administrative operations.",
        recommended_fix="Use parameterized queries / prepared statements. Use an ORM's built-in query builder.",
        cwe="CWE-89",
        owasp="A03:2021",
        file_extensions=(".py", ".js", ".ts", ".php", ".rb", ".java", ".go"),
    ),
    VulnRule(
        id="XSS-001",
        name="Cross-Site Scripting - innerHTML",
        vulnerability_type="XSS",
        pattern=r"(?i)(innerHTML|outerHTML)\s*=\s*[^;]*(?:request|params|query|input|user|data|body|get|post)",
        severity=Severity.HIGH,
        confidence=Confidence.LIKELY,
        description="User input assigned to innerHTML without sanitization.",
        attack_scenario="Attacker injects malicious JavaScript through user-controlled values rendered as HTML.",
        recommended_fix="Use textContent instead of innerHTML, or sanitize with DOMPurify.",
        cwe="CWE-79",
        owasp="A03:2021",
        file_extensions=(".js", ".ts", ".jsx", ".tsx", ".html"),
    ),
    VulnRule(
        id="CSRF-001",
        name="Missing CSRF Protection",
        vulnerability_type="CSRF",
        pattern=r"(?i)(csrf_exempt|@csrf_exempt|disable.*csrf|csrf.*false|csrf.*off)",
        severity=Severity.MEDIUM,
        confidence=Confidence.LIKELY,
        description="CSRF protection explicitly disabled.",
        attack_scenario="Attacker crafts a malicious page that tricks authenticated users into making unintended requests.",
        recommended_fix="Enable CSRF tokens on all state-changing endpoints. Use SameSite cookie attribute.",
        cwe="CWE-352",
        owasp="A01:2021",
    ),
    VulnRule(
        id="CMDI-001",
        name="Command Injection",
        vulnerability_type="Command Injection",
        pattern=r"(?i)(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output|check_call))\s*\(\s*[f\"''].*\{|.*\+\s*(request|params|input|user|arg)",
        severity=Severity.CRITICAL,
        confidence=Confidence.LIKELY,
        description="User input passed to OS command execution functions.",
        attack_scenario="Attacker injects shell commands via semicolons, pipes, or backticks to execute arbitrary code on the server.",
        recommended_fix="Use subprocess with a list of arguments. Validate and sanitize all inputs.",
        cwe="CWE-78",
        owasp="A03:2021",
        file_extensions=(".py",),
    ),
    VulnRule(
        id="AUTH-001",
        name="Hardcoded Password",
        vulnerability_type="Authentication Bypass",
        pattern=r"(?i)(password|passwd|pwd|secret)\s*[:=]\s*['\"''][^'\"'']{4,}['\"'']",
        severity=Severity.HIGH,
        confidence=Confidence.POSSIBLE,
        description="Hardcoded password or secret found in source code.",
        attack_scenario="Attacker finds credentials in source code and uses them to authenticate.",
        recommended_fix="Store secrets in environment variables or a secrets manager.",
        cwe="CWE-798",
        owasp="A07:2021",
    ),
]

_SKIP_DIRS = {
    ".git", ".svn", "__pycache__", "node_modules", "venv",
    ".venv", "dist", "build", ".next", ".nuxt",
}

_SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb",
    ".java", ".go", ".cs", ".rs", ".c", ".cpp", ".h",
    ".html", ".htm", ".vue", ".svelte",
    ".yml", ".yaml", ".json", ".xml", ".toml", ".ini",
    ".cfg", ".conf", ".env", ".sh", ".bash",
}

class VulnerabilityScanner:
    def __init__(self, project_path: str, rules: Optional[list[VulnRule]] = None):
        self.project_path = os.path.abspath(project_path)
        self.rules = rules or VULN_RULES
        self.findings: list[Finding] = []
        self._files_scanned = 0

    def scan(self) -> list[Finding]:
        self.findings.clear()
        self._files_scanned = 0
        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in _SCANNABLE_EXTENSIONS:
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.project_path)
                self._scan_file(fpath, rel_path, ext)
        return self.findings

    def _scan_file(self, fpath: str, rel_path: str, ext: str):
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read(100_000)
        except (OSError, UnicodeDecodeError):
            return
        self._files_scanned += 1
        lines = content.split("\n")
        for rule in self.rules:
            if rule.file_extensions and ext not in rule.file_extensions:
                continue
            try:
                for match in re.finditer(rule.pattern, content):
                    line_num = content[:match.start()].count("\n") + 1
                    if 0 < line_num <= len(lines):
                        evidence_line = lines[line_num - 1].strip()
                    else:
                        evidence_line = match.group(0)[:100]
                    confidence = rule.confidence
                    for neg_pat in rule.negative_patterns:
                        if re.search(neg_pat, content, re.IGNORECASE):
                            confidence = Confidence.POSSIBLE
                            break
                    func_name = self._find_enclosing_function(lines, line_num, ext)
                    finding = Finding(
                        hat=HatType.WHITE,
                        title=rule.name,
                        description=rule.description,
                        severity=rule.severity,
                        confidence=confidence,
                        file=rel_path,
                        line=line_num,
                        function=func_name,
                        vulnerability_type=rule.vulnerability_type,
                        evidence=evidence_line[:200],
                        attack_scenario=rule.attack_scenario,
                        recommended_fix=rule.recommended_fix,
                        cwe=rule.cwe,
                        owasp=rule.owasp,
                    )
                    self.findings.append(finding)
            except re.error:
                continue

    def _find_enclosing_function(self, lines: list[str], line_num: int, ext: str) -> str:
        if ext in (".py",):
            pattern = r'^\s*(def|async\s+def)\s+(\w+)'
        elif ext in (".js", ".ts", ".jsx", ".tsx"):
            pattern = r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=|(\w+)\s*\(.*\)\s*\{|(\w+)\s*:\s*(?:async\s+)?function)'
        elif ext in (".java", ".cs", ".go"):
            pattern = r'(?:(?:public|private|protected|static|func)\s+\w*\s*)?(\w+)\s*\('
        elif ext in (".php",):
            pattern = r'function\s+(\w+)'
        elif ext in (".rb",):
            pattern = r'def\s+(\w+)'
        else:
            return ""
        for i in range(line_num - 1, max(line_num - 100, -1), -1):
            if 0 <= i < len(lines):
                m = re.search(pattern, lines[i])
                if m:
                    for g in m.groups():
                        if g:
                            return g
        return ""

    @property
    def stats(self) -> dict:
        severity_counts = {}
        for f in self.findings:
            key = f.severity.value
            severity_counts[key] = severity_counts.get(key, 0) + 1
        return {
            "files_scanned": self._files_scanned,
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "by_type": self._count_by("vulnerability_type"),
            "by_confidence": self._count_by_confidence(),
        }

    def _count_by(self, attr: str) -> dict:
        counts: dict[str, int] = {}
        for f in self.findings:
            key = getattr(f, attr, "unknown")
            counts[key] = counts.get(key, 0) + 1
        return counts

    def _count_by_confidence(self) -> dict:
        counts: dict[str, int] = {}
        for f in self.findings:
            key = f.confidence.value
            counts[key] = counts.get(key, 0) + 1
        return counts
