from __future__ import annotations
import json
import os
import time
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from .auth_gate import AuthorizationScope, print_policy
from .models import AuditReport
from .pipeline import AuditPipeline
from .report import ReportGenerator

_audit_cache: dict[str, dict] = {}

def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    CORS(app)
    reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    @app.route("/api/scan", methods=["POST"])
    def start_scan():
        data = request.json or {}
        project_path = data.get("project_path", "")
        if not project_path:
            return jsonify({"error": "project_path is required"}), 400
        project_path = os.path.abspath(project_path)
        if not os.path.isdir(project_path):
            return jsonify({"error": f"Not a valid directory: {project_path}"}), 400
        scope = AuthorizationScope(
            project_path=project_path,
            static_analysis_only=True,
            authorized_by="Web Dashboard",
        )
        progress_log = []
        def on_progress(stage, msg):
            progress_log.append({"stage": stage, "message": msg, "time": datetime.now().isoformat()})
        pipeline = AuditPipeline(
            project_path=project_path,
            scope=scope,
            on_progress=on_progress,
        )
        start_time = time.time()
        try:
            report = pipeline.run()
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        elapsed = time.time() - start_time
        gen = ReportGenerator(report)
        report_name = f"audit_{report.project_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        html_path = os.path.join(reports_dir, f"{report_name}.html")
        json_path = os.path.join(reports_dir, f"{report_name}.json")
        gen.generate_html(html_path)
        json_output = gen.generate_json(json_path)
        scan_id = report_name
        _audit_cache[scan_id] = {
            "report": json.loads(json_output),
            "pipeline_stats": pipeline.pipeline_stats,
            "progress_log": progress_log,
            "elapsed": elapsed,
            "html_report": f"{report_name}.html",
            "json_report": f"{report_name}.json",
        }
        return jsonify({
            "scan_id": scan_id,
            "elapsed": round(elapsed, 2),
            "summary": {
                "total_findings": report.total_findings,
                "critical": report.critical_count,
                "high": report.high_count,
                "attack_paths": len(report.attack_paths),
                "assets": len(report.assets),
            },
            "pipeline_stats": pipeline.pipeline_stats,
            "html_report": f"/reports/{report_name}.html",
            "json_report": f"/reports/{report_name}.json",
        })

    @app.route("/api/results/<scan_id>")
    def get_results(scan_id):
        if scan_id not in _audit_cache:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify(_audit_cache[scan_id])

    @app.route("/api/history")
    def list_scans():
        scans = [
            {
                "scan_id": sid,
                "elapsed": data["elapsed"],
                "total_findings": data["report"]["meta"]["total_findings"],
                "project": data["report"]["meta"]["project_name"],
                "timestamp": data["report"]["meta"]["scan_timestamp"],
            }
            for sid, data in _audit_cache.items()
        ]
        return jsonify({"scans": scans})

    @app.route("/api/policy")
    def get_policy():
        return jsonify({"policy": print_policy()})

    @app.route("/reports/<path:filename>")
    def serve_report(filename):
        return send_from_directory(reports_dir, filename)

    @app.route("/")
    def index():
        return _dashboard_html()

    @app.route("/api/health")
    def health():
        return jsonify({"status": "healthy", "version": "1.0.0"})
    return app

def _dashboard_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Hat Security Auditor - Dashboard</title>
    <style>
        :root {
            --bg-primary: #ffffff;
            --bg-card: #f8f9fa;
            --text-primary: #212529;
            --text-secondary: #495057;
            --border: #dee2e6;
            --accent: #0d6efd;
            --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: var(--font); }
        body { background: var(--bg-primary); color: var(--text-primary); padding: 40px 20px; }
        .dashboard { max-width: 800px; margin: 0 auto; }
        .dash-header { margin-bottom: 40px; border-bottom: 2px solid var(--border); padding-bottom: 20px; }
        .dash-header h1 { font-size: 2rem; margin-bottom: 10px; }
        .dash-header p { color: var(--text-secondary); }
        .scan-form { background: var(--bg-card); border: 1px solid var(--border); padding: 20px; border-radius: 4px; margin-bottom: 30px; }
        .scan-form h2 { font-size: 1.2rem; margin-bottom: 15px; }
        .form-row { display: flex; gap: 10px; }
        .form-input { flex: 1; padding: 10px; border: 1px solid var(--border); border-radius: 4px; font-size: 1rem; }
        .scan-btn { padding: 10px 20px; background: var(--accent); border: none; color: white; border-radius: 4px; cursor: pointer; font-size: 1rem; }
        .scan-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .progress-section { display: none; background: var(--bg-card); border: 1px solid var(--border); padding: 20px; border-radius: 4px; margin-bottom: 30px; }
        .progress-section.active { display: block; }
        .progress-title { font-weight: bold; margin-bottom: 10px; }
        .progress-status { font-size: 0.9rem; color: var(--text-secondary); }
        .results-section { display: none; }
        .results-section.active { display: block; }
        .result-summary { background: var(--bg-card); border: 1px solid var(--border); padding: 20px; border-radius: 4px; margin-bottom: 20px; }
        .result-summary h2 { font-size: 1.2rem; margin-bottom: 15px; }
        .report-links a { display: inline-block; padding: 10px 15px; background: #e9ecef; border: 1px solid var(--border); border-radius: 4px; text-decoration: none; color: var(--accent); margin-right: 10px; }
        .history-section { margin-top: 40px; }
        .history-section h2 { font-size: 1.2rem; margin-bottom: 15px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
        .history-item { background: var(--bg-card); border: 1px solid var(--border); padding: 15px; border-radius: 4px; margin-bottom: 10px; cursor: pointer; display: flex; justify-content: space-between; }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="dash-header">
            <h1>Multi-Hat Security Auditor</h1>
            <p>Security testing from six perspectives</p>
        </div>
        <div class="scan-form">
            <h2>Start New Audit</h2>
            <div class="form-row">
                <input type="text" class="form-input" id="projectPath" placeholder="Enter project path" />
                <button class="scan-btn" id="scanBtn" onclick="startScan()">Run Audit</button>
            </div>
        </div>
        <div class="progress-section" id="progressSection">
            <div class="progress-title" id="progressTitle">Running audit...</div>
            <div class="progress-status" id="progressStatus">Initializing...</div>
        </div>
        <div class="results-section" id="resultsSection">
            <div class="result-summary">
                <h2>Audit Results</h2>
                <div id="resultStats"></div>
                <br>
                <div class="report-links" id="reportLinks"></div>
            </div>
        </div>
        <div class="history-section">
            <h2>Previous Scans</h2>
            <div id="historyList">No scans yet.</div>
        </div>
    </div>
    <script>
        async function startScan() {
            const path = document.getElementById('projectPath').value.trim();
            if (!path) return alert('Please enter a project path');
            const btn = document.getElementById('scanBtn');
            const progress = document.getElementById('progressSection');
            const results = document.getElementById('resultsSection');
            btn.disabled = true;
            btn.textContent = 'Scanning...';
            progress.classList.add('active');
            results.classList.remove('active');
            try {
                const resp = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ project_path: path }),
                });
                document.getElementById('progressStatus').textContent = 'Complete!';
                if (!resp.ok) {
                    const err = await resp.json();
                    throw new Error(err.error || 'Scan failed');
                }
                const data = await resp.json();
                showResults(data);
                loadHistory();
            } catch (err) {
                alert('Scan error: ' + err.message);
            } finally {
                btn.disabled = false;
                btn.textContent = 'Run Audit';
                setTimeout(() => progress.classList.remove('active'), 1500);
            }
        }
        function showResults(data) {
            const results = document.getElementById('resultsSection');
            results.classList.add('active');
            const stats = data.summary;
            document.getElementById('resultStats').innerHTML = `
                Total Findings: ${stats.total_findings} | Critical: ${stats.critical} | High: ${stats.high} <br>
                Duration: ${data.elapsed}s
            `;
            document.getElementById('reportLinks').innerHTML = `
                <a href="${data.html_report}" target="_blank">View HTML Report</a>
                <a href="${data.json_report}" target="_blank">View JSON Report</a>
            `;
        }
        async function loadHistory() {
            try {
                const resp = await fetch('/api/history');
                const data = await resp.json();
                if (data.scans.length === 0) return;
                document.getElementById('historyList').innerHTML = data.scans.map(s => `
                    <div class="history-item" onclick="window.open('/reports/${s.scan_id}.html', '_blank')">
                        <span>Project: ${s.project}</span>
                        <span>${s.total_findings} findings</span>
                    </div>
                `).join('');
            } catch (e) {
                console.error('Failed to load history:', e);
            }
        }
        loadHistory();
    </script>
</body>
</html>"""
