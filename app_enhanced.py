"""
SS Tools Enhanced - Optimized Scanner with Reports Menu
- Fast parallel scanning (no hangs)
- JAR contents viewer
- Class file inspector
- Detailed reports
"""

import os
import sys
import json
import time
import tempfile
import shutil
import zipfile
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add scanner imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanner.advanced_detector import (
    parallel_scan_mods, scan_jar_fast, scan_class_fast,
    format_result_for_json, ENHANCED_CHEAT_PATTERNS
)
from scanner.chrome_scanner_enhanced import scan_chrome_history
from scanner.process_scanner_improved import full_process_scan
from scanner.minecraft_scanner_optimized import full_launcher_scan, scan_logs_for_cheats

# Flask setup
app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 10000 * 1024 * 1024

UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "ss-tools-uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Global scan state
scan_state = {
    "running": False,
    "progress": 0,
    "current_task": "",
    "results": None,
    "start_time": None,
    "scan_type": ""
}

# ─── Routes ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    # Use red-themed GUI for .exe builds
    return render_template("index_red_exe.html")


@app.route("/api/info")
def api_info():
    return jsonify({
        "name": "SS Tools Native Enhanced",
        "version": "2.1.0",
        "platform": sys.platform,
        "features": [
            "Fast Mod Scanner (parallel threads)",
            "JAR Contents Viewer",
            "Class File Inspector",
            "DLL Injector Detection",
            "Chrome History Scanner (adult content)",
            "Process Scanner (zero false flags)",
            "Reports with detailed analysis",
            "Auto Launcher Detection",
        ],
        "cheat_signatures": len(ENHANCED_CHEAT_PATTERNS),
    })


# ─── JAR/MOD SCANNING ───────────────────────────────────────────────────

@app.route("/api/scan/mods", methods=["POST"])
def scan_mods():
    """Fast parallel MOD scanning."""
    if "files" not in request.files:
        return jsonify({"error": "No files uploaded"}), 400

    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No files selected"}), 400

    results = []
    temp_dir = os.path.join(UPLOAD_DIR, f"scan_{int(time.time())}")
    os.makedirs(temp_dir, exist_ok=True)

    mod_paths = []
    try:
        for f in files:
            if not f.filename:
                continue

            safe_name = os.path.basename(f.filename).replace("..", "")
            fpath = os.path.join(temp_dir, safe_name)
            f.save(fpath)
            mod_paths.append(fpath)

        # Parallel scan with timeout
        scan_results = parallel_scan_mods(mod_paths, max_workers=8, timeout=60)
        
        for result in scan_results:
            results.append(format_result_for_json(result))

        # Summary
        total = len(results)
        flagged = sum(1 for r in results if r.get("is_cheat"))
        critical = sum(1 for r in results if r.get("risk_level") == "CRITICAL")

        return jsonify({
            "total_files": total,
            "flagged": flagged,
            "critical": critical,
            "clean": total - flagged,
            "verdict": "FLAGGED" if flagged > 0 else "CLEAN",
            "results": results,
            "scan_time": datetime.now().isoformat()
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        # Cleanup after delay
        def cleanup():
            time.sleep(60)
            shutil.rmtree(temp_dir, ignore_errors=True)
        threading.Thread(target=cleanup, daemon=True).start()


# ─── JAR CONTENTS VIEWER ───────────────────────────────────────────────

@app.route("/api/jar/contents", methods=["POST"])
def jar_contents():
    """View all files inside a JAR."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "No file selected"}), 400

    temp_dir = os.path.join(UPLOAD_DIR, f"jar_view_{int(time.time())}")
    os.makedirs(temp_dir, exist_ok=True)

    try:
        safe_name = os.path.basename(f.filename).replace("..", "")
        fpath = os.path.join(temp_dir, safe_name)
        f.save(fpath)

        contents = {
            "filename": safe_name,
            "files": [],
            "class_files": [],
            "suspicious_files": [],
            "statistics": {
                "total_files": 0,
                "class_files": 0,
                "resource_files": 0,
                "config_files": 0
            }
        }

        try:
            with zipfile.ZipFile(fpath, 'r') as zf:
                for entry in zf.namelist():
                    contents["files"].append({
                        "name": entry,
                        "size": zf.getinfo(entry).file_size,
                        "type": "class" if entry.endswith(".class") else
                                "config" if entry.endswith((".json", ".properties", ".yaml", ".yml")) else
                                "resource" if entry.endswith((".png", ".txt", ".md")) else "other"
                    })

                    if entry.endswith(".class"):
                        contents["class_files"].append(entry)
                        contents["statistics"]["class_files"] += 1
                    elif entry.endswith((".json", ".properties", ".yaml", ".yml")):
                        contents["statistics"]["config_files"] += 1
                    else:
                        contents["statistics"]["resource_files"] += 1

                    # Check for suspicious files
                    entry_lower = entry.lower()
                    if any(pattern in entry_lower for pattern in ["cheat", "inject", "hook", "xray", "esp", "bot", "aimbot"]):
                        contents["suspicious_files"].append(entry)

                contents["statistics"]["total_files"] = len(contents["files"])

        except zipfile.BadZipFile:
            return jsonify({"error": "Invalid JAR/ZIP file"}), 400

        # Cleanup
        def cleanup():
            time.sleep(60)
            shutil.rmtree(temp_dir, ignore_errors=True)
        threading.Thread(target=cleanup, daemon=True).start()

        return jsonify(contents)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── CLASS FILE INSPECTOR ───────────────────────────────────────────────

@app.route("/api/class/inspect", methods=["POST"])
def inspect_class():
    """Inspect a single CLASS file."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "No file selected"}), 400

    temp_dir = os.path.join(UPLOAD_DIR, f"class_{int(time.time())}")
    os.makedirs(temp_dir, exist_ok=True)

    try:
        safe_name = os.path.basename(f.filename).replace("..", "")
        fpath = os.path.join(temp_dir, safe_name)
        f.save(fpath)

        result = scan_class_fast(fpath)

        # Cleanup
        def cleanup():
            time.sleep(60)
            shutil.rmtree(temp_dir, ignore_errors=True)
        threading.Thread(target=cleanup, daemon=True).start()

        return jsonify(format_result_for_json(result))

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── CHROME SCANNER ─────────────────────────────────────────────────────

@app.route("/api/scan/browser")
def scan_browser():
    """Fast Chrome history scan."""
    try:
        result = scan_chrome_history()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── PROCESS SCANNER ────────────────────────────────────────────────────

@app.route("/api/scan/processes")
def scan_processes():
    """Process scanner (no false flags)."""
    try:
        result = full_process_scan()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── MINECRAFT AUTO SCAN ────────────────────────────────────────────────

@app.route("/api/scan/minecraft-fast")
def minecraft_fast_scan():
    """Fast Minecraft launcher detection and scan."""
    if scan_state["running"]:
        return jsonify({"error": "Scan already running"}), 400

    def run_scan():
        scan_state["running"] = True
        scan_state["progress"] = 0
        scan_state["current_task"] = "Detecting Minecraft launchers..."
        scan_state["start_time"] = time.time()
        scan_state["scan_type"] = "minecraft"
        scan_state["results"] = {}

        try:
            # Detect launchers
            scan_state["progress"] = 10
            launchers = full_launcher_scan()
            scan_state["results"]["launchers"] = launchers

            # Collect mod paths from all launchers
            mod_paths = []
            scan_state["current_task"] = "Collecting mod files..."
            scan_state["progress"] = 20

            for launcher in launchers.get("launchers", []):
                for mod in launcher.get("mods", []):
                    if mod.get("path") and os.path.isfile(mod["path"]):
                        mod_paths.append(mod["path"])

            # Parallel scan all mods
            scan_state["current_task"] = f"Scanning {len(mod_paths)} mods..."
            scan_state["progress"] = 30

            scan_results = parallel_scan_mods(mod_paths, max_workers=12, timeout=120)

            flagged = [r for r in scan_results if r.is_cheat]
            critical = [r for r in scan_results if r.risk_level == "CRITICAL"]

            scan_state["results"]["mods"] = {
                "total": len(scan_results),
                "flagged": len(flagged),
                "critical": len(critical),
                "clean": len(scan_results) - len(flagged),
                "results": [format_result_for_json(r) for r in scan_results]
            }

            scan_state["progress"] = 100
            scan_state["current_task"] = "Scan complete!"
            elapsed = round(time.time() - scan_state["start_time"], 1)
            scan_state["results"]["elapsed_seconds"] = elapsed

        except Exception as e:
            scan_state["results"]["error"] = str(e)
            scan_state["current_task"] = f"Error: {str(e)}"
        finally:
            scan_state["running"] = False

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({"status": "started"})


# ─── FULL AUTO SCAN ─────────────────────────────────────────────────────

@app.route("/api/scan/full-auto-fast")
def full_auto_scan_fast():
    """Full system scan (all modules, optimized)."""
    if scan_state["running"]:
        return jsonify({"error": "Scan already running"}), 400

    def run_scan():
        scan_state["running"] = True
        scan_state["progress"] = 0
        scan_state["current_task"] = "Starting full system scan..."
        scan_state["start_time"] = time.time()
        scan_state["scan_type"] = "full"
        scan_state["results"] = {}

        try:
            # 1. Minecraft scan (30%)
            scan_state["current_task"] = "Detecting Minecraft launchers..."
            scan_state["progress"] = 5
            launchers = full_launcher_scan()

            scan_state["current_task"] = "Collecting mods..."
            scan_state["progress"] = 10
            mod_paths = []
            for launcher in launchers.get("launchers", []):
                for mod in launcher.get("mods", []):
                    if mod.get("path") and os.path.isfile(mod["path"]):
                        mod_paths.append(mod["path"])

            scan_state["current_task"] = "Scanning mods (parallel)..."
            scan_state["progress"] = 15
            scan_results = parallel_scan_mods(mod_paths, max_workers=12, timeout=120)
            scan_state["results"]["mods"] = {
                "total": len(scan_results),
                "flagged": sum(1 for r in scan_results if r.is_cheat),
                "results": [format_result_for_json(r) for r in scan_results[:50]]  # Limit for response
            }
            scan_state["progress"] = 30

            # 2. Process scan (20%)
            scan_state["current_task"] = "Scanning running processes..."
            scan_state["progress"] = 35
            scan_state["results"]["processes"] = full_process_scan()
            scan_state["progress"] = 50

            # 3. Browser scan (20%)
            scan_state["current_task"] = "Scanning browser history..."
            scan_state["progress"] = 55
            scan_state["results"]["browser"] = scan_chrome_history()
            scan_state["progress"] = 70

            # Summary
            scan_state["current_task"] = "Generating report..."
            scan_state["progress"] = 90

            total_flags = (
                scan_state["results"]["mods"].get("flagged", 0) +
                len(scan_state["results"]["processes"].get("suspicious_processes", [])) +
                len(scan_state["results"]["browser"].get("adult_sites", []))
            )

            scan_state["results"]["summary"] = {
                "total_flags": total_flags,
                "verdict": "CLEAN" if total_flags == 0 else "FLAGGED",
                "elapsed_seconds": round(time.time() - scan_state["start_time"], 1),
                "scan_time": datetime.now().isoformat()
            }

            scan_state["progress"] = 100
            scan_state["current_task"] = "Complete!"

        except Exception as e:
            scan_state["results"]["error"] = str(e)
        finally:
            scan_state["running"] = False

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({"status": "started", "message": "Full auto scan started"})


# ─── SCAN STATUS & RESULTS ────────────────────────────────────────────

@app.route("/api/scan/status")
def scan_status():
    """Get scan progress."""
    return jsonify({
        "running": scan_state["running"],
        "progress": scan_state["progress"],
        "current_task": scan_state["current_task"],
        "scan_type": scan_state["scan_type"]
    })


@app.route("/api/scan/results")
def scan_results():
    """Get scan results."""
    if scan_state["results"] is None:
        return jsonify({"error": "No scan results"}), 400
    return jsonify(scan_state["results"])


# ─── MAIN ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    mode = os.environ.get("MODE", "desktop")

    if mode == "web":
        print(f"Starting SS Tools on http://localhost:{port}")
        app.run(host="0.0.0.0", port=port, debug=False)
    else:
        try:
            import webview
            flask_thread = threading.Thread(
                target=lambda: app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
                daemon=True
            )
            flask_thread.start()

            time.sleep(1)
            webview.create_window(
                "SS Tools Native v2.1",
                f"http://127.0.0.1:{port}",
                width=1400,
                height=900,
                resizable=True
            )
            webview.start(debug=False)
        except ImportError:
            print(f"Open http://localhost:{port} in browser")
            app.run(host="0.0.0.0", port=port, debug=False)
