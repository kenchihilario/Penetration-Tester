# Multi-Hat Security Auditor

Security agent that reviews projects from six security perspectives, identifies vulnerabilities, validates findings, and produces remediation guidance.

## Security Hats

| Hat | Role | Focus |
|-----|------|-------|
| White Hat | Authorized Pen Tester | Static analysis, vulnerability scanning, dependency checks |
| Red Hat | Adversarial Attacker | Attack path modeling, exploit chain analysis |
| Blue Hat | Defender / SOC Analyst | Detection gaps, logging, alerting, IOC analysis |
| Purple Hat | Red + Blue Validation | Offensive/defensive cross-validation |
| Gray Hat | Edge-Case Researcher | Business logic, race conditions, trust boundaries |
| Code Review | Secure Code Reviewer | Function-level vulnerability analysis |

## Quick Start

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run a scan:
```bash
python main.py scan ../CalculatorWithATwist
```

3. Launch the web dashboard:
```bash
python main.py serve --port 8765
```

## Security Testing Policy

1. Determine the target
2. Determine whether the target is explicitly authorized
3. Prefer localhost, test containers, dev/staging servers
4. Never attack arbitrary external systems
5. Never steal, dump, or publish credentials
6. Never destroy or corrupt data
7. Never establish persistence
8. Never evade security monitoring
9. Never use findings to attack unrelated systems
10. Stop when testing could affect systems outside scope
