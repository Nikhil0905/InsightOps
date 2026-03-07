"""
InsightOps Web Server — Flask backend with SSE streaming.
Serves the static landing page and provides API endpoints
to execute the AI pipeline and tests in real-time.
"""

import subprocess
import sys
import os
from pathlib import Path
from flask import Flask, Response, send_from_directory, jsonify, request

# ---------------------------------------------------------------------------
# Load .env so credentials are available to subprocesses run from the web UI
# ---------------------------------------------------------------------------
_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
if _ENV_FILE.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(_ENV_FILE, override=False)
    except ImportError:
        # dotenv not installed — parse manually
        with open(_ENV_FILE) as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _, _v = _line.partition("=")
                    # strip 'export ' prefix if present
                    _k = _k.strip().removeprefix("export ").strip()
                    _v = _v.strip().strip('"').strip("'")
                    os.environ.setdefault(_k, _v)

# Resolve project paths
WEB_DIR = Path(__file__).resolve().parent
REPO_ROOT = WEB_DIR.parent
AI_ENGINE_MAIN = REPO_ROOT / "ai-engine" / "main.py"
TESTS_DIR = REPO_ROOT / "tests"

app = Flask(__name__, static_folder=str(WEB_DIR), static_url_path="")

# ---------------------------------------------------------------------------
# Static file serving
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(str(WEB_DIR), "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(str(WEB_DIR), filename)


# Serve gallery images from docs/Images_Proof/ (avoids duplicating images into web/)
IMAGES_DIR = REPO_ROOT / "docs" / "Images_Proof"


@app.route("/gallery/<path:filename>")
def gallery_images(filename):
    return send_from_directory(str(IMAGES_DIR), filename)


# ---------------------------------------------------------------------------
# SSE streaming helper
# ---------------------------------------------------------------------------

def _stream_subprocess(cmd: list[str], cwd: str | None = None):
    """
    Spawn a subprocess and yield its stdout/stderr as SSE events.
    Each line becomes a `data:` event with a JSON payload containing
    the line text and stream type (stdout/stderr).
    """
    import json
    import select

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env,
        text=True,
        bufsize=1,
    )

    # Use select to interleave stdout and stderr
    import selectors
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ, "stdout")
    sel.register(proc.stderr, selectors.EVENT_READ, "stderr")

    active_streams = 2
    while active_streams > 0:
        for key, _ in sel.select(timeout=0.1):
            line = key.fileobj.readline()
            if line:
                payload = json.dumps({
                    "stream": key.data,
                    "line": line.rstrip("\n"),
                })
                yield f"data: {payload}\n\n"
            else:
                sel.unregister(key.fileobj)
                active_streams -= 1

    proc.wait()
    done_payload = json.dumps({
        "stream": "system",
        "line": f"[Process exited with code {proc.returncode}]",
        "exit_code": proc.returncode,
        "done": True,
    })
    yield f"data: {done_payload}\n\n"


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/run-pipeline")
def run_pipeline():
    """Run the InsightOps AI pipeline and stream output via SSE."""
    mode = request.args.get("mode", "dry-run")
    cmd = [sys.executable, str(AI_ENGINE_MAIN)]
    if mode == "dry-run":
        cmd.append("--dry-run")

    return Response(
        _stream_subprocess(cmd, cwd=str(REPO_ROOT)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.route("/api/run-tests")
def run_tests():
    """Run pytest on the test suite and stream output via SSE."""
    cmd = [sys.executable, "-m", "pytest", str(TESTS_DIR), "-v", "--tb=short", "--no-header"]

    return Response(
        _stream_subprocess(cmd, cwd=str(REPO_ROOT)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.route("/api/status")
def status():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "engine": str(AI_ENGINE_MAIN),
        "engine_exists": AI_ENGINE_MAIN.exists(),
        "tests_dir": str(TESTS_DIR),
        "tests_exist": TESTS_DIR.exists(),
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"🚀 InsightOps Web Server")
    print(f"   Static files: {WEB_DIR}")
    print(f"   AI Engine:    {AI_ENGINE_MAIN}")
    print(f"   Open:         http://localhost:5000")
    print()
    app.run(host="0.0.0.0", port=5000, debug=True)
