 Security Hats

| Hat | Role | Focus |
|-----|------|-------|
| White Hat | Authorized Pen Tester | Static analysis, vulnerability scanning, dependency checks |
| Red Hat | Adversarial Attacker | Attack path modeling, exploit chain analysis |
| Blue Hat | Defender / SOC Analyst | Detection gaps, logging, alerting, IOC analysis |
| Purple Hat | Red + Blue Validation | Offensive/defensive cross-validation |
| Gray Hat | Edge-Case Researcher | Business logic, race conditions, trust boundaries |
| Code Review | Secure Code Reviewer | Function-level vulnerability analysis |


1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run a scan:
```bash
python main.py scan ../arandomfolder
```

3. Launch the web dashboard:
```bash
python main.py serve --port 8765
```
