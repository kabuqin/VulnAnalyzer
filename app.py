#!/usr/bin/env python3
import sys
import json
import time
import queue
import threading
from pathlib import Path

BASE = Path(__file__).parent
sys.path.insert(0, str(BASE))

from flask import Flask, request, jsonify, send_from_directory, Response
import vuln_analyzer
import crawler

app = Flask(__name__, static_folder="static", static_url_path="/static")


@app.after_request
def add_no_cache(response):
    """Disable caching for development freshness."""
    if 'text/html' in response.content_type:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text", "").strip()
    min_risk = data.get("min_risk", "info")
    types = data.get("types") or None

    if not text:
        return jsonify({"error": "No input provided"}), 400

    enabled = set(types) if types else None
    result = vuln_analyzer.analyze(text, source_name="paste", enabled_types=enabled)
    result = vuln_analyzer.apply_filters(result, min_risk)
    return jsonify(result)


@app.route("/crawl", methods=["POST"])
def crawl_target():
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target", "").strip()
    max_pages = data.get("max_pages", 30)

    if not target:
        return jsonify({"error": "Target URL required"}), 400

    try:
        result = crawler.crawl_and_extract(target, max_pages=max_pages)
        # Return lightweight summary for the crawl-only endpoint
        result["pages"] = result.get("pages_summary", [])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/scan-target", methods=["POST"])
def scan_target():
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target", "").strip()
    min_risk = data.get("min_risk", "info")
    max_pages = data.get("max_pages", 30)

    if not target:
        return jsonify({"error": "Target URL required"}), 400

    try:
        crawl_result = crawler.crawl_and_extract(target, max_pages=max_pages)
        all_findings = []

        # Scan each crawled page's HTML content
        for url, html, status in crawl_result.get("pages", []):
            if status == 0 or status >= 400:
                continue
            mock_response = (
                f"HTTP/1.1 {status} OK\r\n"
                f"Content-Type: text/html\r\n\r\n"
                f"{html[:10000]}"
            )
            result = vuln_analyzer.analyze(mock_response, source_name=url)
            all_findings.extend(result.get("findings", []))

        # Scan forms
        for form in crawl_result.get("forms", []):
            form_text = str(form)
            result = vuln_analyzer.analyze(
                form_text, source_name=f"form @ {form.get('url', target)}"
            )
            all_findings.extend(result.get("findings", []))

        # Scan URL parameters
        for param in crawl_result.get("params", []):
            param_text = f"{param['name']}={param['value']}"
            result = vuln_analyzer.analyze(
                param_text, source_name=f"param @ {param.get('url', target)}"
            )
            all_findings.extend(result.get("findings", []))

        # Deduplicate findings
        seen_keys = set()
        unique_findings = []
        for f in all_findings:
            key = (f["type"], f["location"], f["evidence"])
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)

        # Filter by minimum risk level
        min_order = vuln_analyzer.RISK_ORDER.get(min_risk, 0)
        filtered = [
            f for f in unique_findings
            if vuln_analyzer.RISK_ORDER.get(f["risk"], 0) >= min_order
        ]

        by_risk = {}
        for f in filtered:
            by_risk[f["risk"]] = by_risk.get(f["risk"], 0) + 1

        return jsonify({
            "target": target,
            "status": "completed",
            "pages_crawled": crawl_result.get("pages_crawled", 0),
            "forms_found": len(crawl_result.get("forms", [])),
            "params_found": len(crawl_result.get("params", [])),
            "errors": crawl_result.get("errors", []),
            "findings": filtered,
            "summary": {
                "total_findings": len(filtered),
                "by_risk": by_risk,
                "input_type": "web_scan",
            },
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/scan-stream", methods=["POST"])
def scan_stream():
    """SSE endpoint for real-time scan progress."""
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target", "").strip()
    min_risk = data.get("min_risk", "info")
    max_pages = data.get("max_pages", 30)

    if not target:
        return jsonify({"error": "Target URL required"}), 400

    def event_stream():
        messages = queue.Queue()

        def on_progress(msg):
            messages.put(msg)

        def do_scan():
            try:
                on_progress(f"Initializing scan of {target}...")
                crawl_result = crawler.crawl_and_extract(
                    target, max_pages=max_pages, on_progress=on_progress
                )
                on_progress(
                    f"Crawl complete: {crawl_result['pages_crawled']} pages, "
                    f"{len(crawl_result.get('forms', []))} forms found"
                )
                on_progress("Starting vulnerability analysis...")

                all_findings = []
                pages = crawl_result.get("pages", [])
                for i, (url, html, status) in enumerate(pages):
                    if status == 0 or status >= 400:
                        continue
                    on_progress(
                        f"Analyzing page {i+1}/{len(pages)}: {url[:70]}"
                    )
                    mock_response = (
                        f"HTTP/1.1 {status} OK\r\n"
                        f"Content-Type: text/html\r\n\r\n"
                        f"{html[:10000]}"
                    )
                    result = vuln_analyzer.analyze(mock_response, source_name=url)
                    all_findings.extend(result.get("findings", []))

                for form in crawl_result.get("forms", []):
                    form_text = str(form)
                    result = vuln_analyzer.analyze(
                        form_text,
                        source_name=f"form @ {form.get('url', target)}"
                    )
                    all_findings.extend(result.get("findings", []))

                for param in crawl_result.get("params", []):
                    param_text = f"{param['name']}={param['value']}"
                    result = vuln_analyzer.analyze(
                        param_text,
                        source_name=f"param @ {param.get('url', target)}"
                    )
                    all_findings.extend(result.get("findings", []))

                # Deduplicate
                seen_keys = set()
                unique_findings = []
                for f in all_findings:
                    key = (f["type"], f["location"], f["evidence"])
                    if key not in seen_keys:
                        seen_keys.add(key)
                        unique_findings.append(f)

                min_order = vuln_analyzer.RISK_ORDER.get(min_risk, 0)
                filtered = [
                    f for f in unique_findings
                    if vuln_analyzer.RISK_ORDER.get(f["risk"], 0) >= min_order
                ]

                by_risk = {}
                for f in filtered:
                    by_risk[f["risk"]] = by_risk.get(f["risk"], 0) + 1

                final_result = {
                    "target": target,
                    "status": "completed",
                    "pages_crawled": crawl_result.get("pages_crawled", 0),
                    "forms_found": len(crawl_result.get("forms", [])),
                    "params_found": len(crawl_result.get("params", [])),
                    "errors": crawl_result.get("errors", []),
                    "findings": filtered,
                    "summary": {
                        "total_findings": len(filtered),
                        "by_risk": by_risk,
                        "input_type": "web_scan",
                    },
                }
                on_progress(f"Scan complete! Found {len(filtered)} issues.")
                messages.put(("__RESULT__", final_result))
            except Exception as e:
                messages.put(("__ERROR__", str(e)))

        thread = threading.Thread(target=do_scan, daemon=True)
        thread.start()

        while True:
            try:
                msg = messages.get(timeout=60)
                if isinstance(msg, tuple):
                    tag, payload = msg
                    if tag == "__RESULT__":
                        yield f"data: {json.dumps({'type': 'result', 'data': payload})}\n\n"
                        return
                    elif tag == "__ERROR__":
                        yield f"data: {json.dumps({'type': 'error', 'data': payload})}\n\n"
                        return
                else:
                    yield f"data: {json.dumps({'type': 'progress', 'data': msg})}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    print("\nVulnAnalyzer v2.2")
    print("http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
