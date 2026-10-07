from __future__ import annotations
import argparse
import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auditor.auth_gate import AuthorizationScope, print_policy
from auditor.pipeline import AuditPipeline
from auditor.report import ReportGenerator

def _print_banner():
    banner = r"""
==============================================================
    Multi-Hat Security Auditor v1.0                      
                                                              
    White Hat    Red Hat     Blue Hat                
    Purple Hat   Gray Hat    Code Review            
==============================================================
    """
    print(banner)

def _progress_callback(stage: str, message: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  [{ts}] {stage}: {message}")

def _print_console_report(report):
    from auditor.models import Severity, HatType
    all_findings = report.findings + report.gray_hat_notes
    print("\n" + "=" * 60)
    print(f"  EXECUTIVE SUMMARY")
    print("=" * 60)
    print(report.executive_summary)
    print()
    if not all_findings:
        print("  No vulnerabilities detected.")
        return
    all_findings.sort(key=lambda f: f.risk_score, reverse=True)
    print("=" * 60)
    print(f"  TOP FINDINGS (sorted by risk)")
    print("=" * 60)
    for i, f in enumerate(all_findings[:15], 1):
        conf = f.confidence.value
        print(f"\n  {i}. [{f.severity.value.upper()}] {f.title}")
        print(f"     Confidence: {conf} | Risk Score: {f.risk_score}")
        print(f"     File: {f.file}" + (f" Line: {f.line}" if f.line else ""))
        if f.function:
            print(f"     Function: {f.function}")
        if f.evidence:
            print(f"     Evidence: {f.evidence[:100]}")
        if f.recommended_fix:
            print(f"     Fix: {f.recommended_fix[:100]}")
        if f.cwe:
            print(f"     {f.cwe}" + (f" | {f.owasp}" if f.owasp else ""))
    if report.attack_paths:
        print(f"\n{'=' * 60}")
        print(f"  ATTACK PATHS ({len(report.attack_paths)} modeled)")
        print("=" * 60)
        for ap in report.attack_paths:
            print(f"\n  Objective: {ap.objective}")
            print(f"     Severity: [{ap.severity.value.upper()}] | Likelihood: {ap.likelihood}")
            print(f"     Steps: {len(ap.steps)}")
            for step in ap.steps:
                print(f"       {step.order}. {step.description}")
            print(f"     Impact: {ap.expected_impact}")
    if report.purple_validations:
        print(f"\n{'=' * 60}")
        print(f"  PURPLE HAT VALIDATIONS")
        print("=" * 60)
        for pv in report.purple_validations:
            retest = "RETEST NEEDED" if pv.retest_needed else "VALIDATED"
            print(f"\n  Status: {pv.result.value.replace('_', ' ')}")
            print(f"     Gap: {pv.gap_analysis}")
            print(f"     {retest}")
    remaining = len(all_findings) - 15
    if remaining > 0:
        print(f"\n  ... and {remaining} more findings. See full report for details.")

def cmd_scan(args):
    _print_banner()
    project_path = os.path.abspath(args.target)
    if not os.path.isdir(project_path):
        print(f"  Error: '{project_path}' is not a valid directory.")
        sys.exit(1)
    print(f"  Target: {project_path}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    scope = AuthorizationScope(
        project_path=project_path,
        static_analysis_only=True,
        authorized_by="CLI user",
        authorization_notes="Local static analysis only",
    )
    start_time = time.time()
    pipeline = AuditPipeline(
        project_path=project_path,
        scope=scope,
        on_progress=_progress_callback,
    )
    try:
        report = pipeline.run()
    except Exception as e:
        print(f"\n  Pipeline error: {e}")
        sys.exit(1)
    elapsed = time.time() - start_time
    print(f"\n  Audit completed in {elapsed:.1f}s")
    if args.json:
        gen = ReportGenerator(report)
        output_path = args.output or os.path.join(
            os.path.dirname(project_path), "pentest_report.json"
        )
        gen.generate_json(output_path)
        print(f"  JSON report saved to: {output_path}")
    elif args.console:
        _print_console_report(report)
    else:
        gen = ReportGenerator(report)
        output_path = args.output or os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "reports",
            f"audit_{report.project_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
        )
        gen.generate_html(output_path)
        print(f"  HTML report saved to: {output_path}")
    stats = pipeline.pipeline_stats
    print(f"\n  Pipeline Statistics:")
    for s in stats["stages"]:
        status_text = "Done" if s["status"] == "done" else "Failed"
        print(f"    [{status_text}] {s['name']}: {s['items']} items ({s['duration']})")
    print(f"    Total: {stats['total_duration']}")

def cmd_serve(args):
    _print_banner()
    print("  Starting web dashboard...")
    try:
        from auditor.web_dashboard import create_app
        app = create_app()
        port = args.port or 8765
        print(f"  Dashboard running at: http://localhost:{port}")
        print(f"  Press Ctrl+C to stop.\n")
        app.run(host="0.0.0.0", port=port, debug=False)
    except ImportError as e:
        print(f"  Flask not installed. Install with: pip install flask flask-cors")
        print(f"  Error: {e}")
        sys.exit(1)

def cmd_policy(args):
    _print_banner()
    print(print_policy())

def main():
    parser = argparse.ArgumentParser(
        description="Multi-Hat Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    scan_parser = subparsers.add_parser("scan", help="Run a full security audit")
    scan_parser.add_argument("target", help="Path to the project to audit")
    scan_parser.add_argument("--json", action="store_true", help="Output as JSON")
    scan_parser.add_argument("--console", action="store_true", help="Console output only")
    scan_parser.add_argument("--output", "-o", help="Custom output file path")
    serve_parser = subparsers.add_parser("serve", help="Launch web dashboard")
    serve_parser.add_argument("--port", "-p", type=int, default=8765, help="Port (default: 8765)")
    subparsers.add_parser("policy", help="Print security testing policy")
    args = parser.parse_args()
    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "serve":
        cmd_serve(args)
    elif args.command == "policy":
        cmd_policy(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
