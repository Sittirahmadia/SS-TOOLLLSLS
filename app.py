"""
SS Tools Native - Minecraft Screen Share Anti-Cheat Scanner
A comprehensive tool for detecting cheats, macros, injectors, and suspicious activity.
Runs as both a web application and can be compiled to .exe.
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

# Add parent to path for scanner imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.cheat_detector import detect_cheats, get_all_signatures, is_whitelisted
from scanner.jar_inspector import inspect_jar, scan_mods_directory, read_jar_entries
from scanner.minecraft_scanner import detect_launchers, full_launcher_scan, get_mod_files
from scanner.deleted_files import scan_deleted_files
from scanner.process_scanner import full_process_scan
from scanner.chrome_scanner import scan_chrome_history
from scanner.kernel_checker import full_kernel_check
from scanner.string_scanner import (
    scan_file_strings, scan_directory_for_strings,
    scan_task_manager_binaries, extract_strings
)

# ── Flask App ──────────────────────────────────────────────
app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

# 10 GB max upload
app.config["MAX_CONTENT_LENGTH"] = 10000 * 1024 * 1024  # 10000 MB

UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "ss-tools-uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Global scan state
scan_state = {
    "running": False,
    "progress": 0,
    "current_task": "",
    "results": None,
    "start_time": None,
}


# ── Routes ─────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/info")
def api_info():
    return jsonify({
        "name": "SS Tools Native",
        "version": "2.0.0",
        "platform": sys.platform,
        "signatures": len(get_all_signatures()),
        "features": [
            "Mod Scanner (JAR/ZIP inspection)",
            "Cheat String Detection",
            "Deleted File Scanner",
            "Process Scanner",
            "Chrome History Scanner",
            "Kernel-Level Checker",
            "String / DLL / EXE Scanner",
            "Auto Launcher Detection",
            "Class File Inspector",
        ],
    })


@app.route("/api/signatures")
def api_signatures():
    return jsonify(get_all_signatures())


# ── Upload & Scan Mods ─────────────────────────────────────

@app.route("/api/upload-mods", methods=["POST"])
def upload_mods():
    """Upload and scan mod files (.jar, .zip)."""
    if "files" not in request.files:
        return jsonify({"error": "No files uploaded"}), 400

    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No files selected"}), 400

    results = []
    scan_dir = os.path.join(UPLOAD_DIR, f"scan_{int(time.time())}")
    os.makedirs(scan_dir, exist_ok=True)

    try:
        for f in files:
            if not f.filename:
                continue

            # Sanitize filename
            safe_name = f.filename.replace("..", "").replace("/", "_").replace("\\", "_")
            fpath = os.path.join(scan_dir, safe_name)
            f.save(fpath)

            ext = os.path.splitext(safe_name)[1].lower()
            if ext in (".jar", ".zip"):
                result = inspect_jar(fpath)
                results.append(result)
            else:
                # String scan for other files
                result = scan_file_strings(fpath)
                results.append(result)

        # Summary
        total = len(results)
        flagged = sum(1 for r in results if r.get("flagged") or r.get("cheat_detections"))
        safe = sum(1 for r in results if r.get("safe") or r.get("whitelisted"))

        return jsonify({
            "total_files": total,
            "flagged": flagged,
            "safe": safe,
            "results": results,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        # Cleanup after delay
        def cleanup():
            time.sleep(60)
            shutil.rmtree(scan_dir, ignore_errors=True)
        threading.Thread(target=cleanup, daemon=True).start()


@app.route("/api/upload-folder", methods=["POST"])
def upload_folder():
    """Upload an entire mods folder (as multiple files)."""
    if "files" not in request.files:
        return jsonify({"error": "No files uploaded"}), 400

    files = request.files.getlist("files")
    results = []
    scan_dir = os.path.join(UPLOAD_DIR, f"folder_{int(time.time())}")
    os.makedirs(scan_dir, exist_ok=True)

    try:
        for f in files:
            if not f.filename:
                continue
            safe_name = os.path.basename(f.filename.replace("..", "").replace("\\", "/"))
            fpath = os.path.join(scan_dir, safe_name)
            f.save(fpath)

        # Scan the whole directory
        results = scan_mods_directory(scan_dir)

        total = len(results)
        flagged = sum(1 for r in results if r.get("flagged"))
        safe = sum(1 for r in results if r.get("safe") or r.get("whitelisted"))

        return jsonify({
            "total_files": total,
            "flagged": flagged,
            "safe": safe,
            "results": results,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        def cleanup():
            time.sleep(60)
            shutil.rmtree(scan_dir, ignore_errors=True)
        threading.Thread(target=cleanup, daemon=True).start()


# ── JAR Inspector ──────────────────────────────────────────

@app.route("/api/inspect-jar", methods=["POST"])
def api_inspect_jar():
    """Upload and deeply inspect a single JAR file."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "No file selected"}), 400

    scan_dir = os.path.join(UPLOAD_DIR, f"jar_{int(time.time())}")
    os.makedirs(scan_dir, exist_ok=True)

    try:
        safe_name = f.filename.replace("..", "").replace("/", "_").replace("\\", "_")
        fpath = os.path.join(scan_dir, safe_name)
        f.save(fpath)

        result = inspect_jar(fpath)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        def cleanup():
            time.sleep(60)
            shutil.rmtree(scan_dir, ignore_errors=True)
        threading.Thread(target=cleanup, daemon=True).start()


# ── Class File Inspector ───────────────────────────────────

@app.route("/api/inspect-class", methods=["POST"])
def api_inspect_class():
    """Upload a .class or .jar file and extract all strings for inspection."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "No file selected"}), 400

    scan_dir = os.path.join(UPLOAD_DIR, f"class_{int(time.time())}")
    os.makedirs(scan_dir, exist_ok=True)

    try:
        safe_name = f.filename.replace("..", "").replace("/", "_").replace("\\", "_")
        fpath = os.path.join(scan_dir, safe_name)
        f.save(fpath)

        ext = os.path.splitext(safe_name)[1].lower()
        all_strings = []
        class_files = []
        all_detections = []

        if ext == ".class":
            # Single class file
            with open(fpath, "rb") as cf:
                class_bytes = cf.read()
            from scanner.jar_inspector import extract_strings_from_class
            strings = extract_strings_from_class(class_bytes)
            all_strings = strings
            class_files = [safe_name]

            # Run detection
            content = " ".join(strings)
            detections = detect_cheats(content, safe_name, fpath)
            all_detections = detections

        elif ext in (".jar", ".zip"):
            # JAR/ZIP — extract strings from all class files
            import zipfile
            from scanner.jar_inspector import extract_strings_from_class
            try:
                with zipfile.ZipFile(fpath, "r") as zf:
                    for entry in zf.namelist():
                        if entry.lower().endswith(".class"):
                            class_files.append(entry)
                            try:
                                class_bytes = zf.read(entry)
                                strings = extract_strings_from_class(class_bytes)
                                all_strings.extend(strings)
                            except Exception:
                                continue
            except zipfile.BadZipFile:
                return jsonify({"error": "Invalid or corrupted JAR/ZIP file"})

            # Run detection on all combined strings
            content = " ".join(all_strings)
            detections = detect_cheats(content, safe_name, fpath)
            all_detections = detections
        else:
            return jsonify({"error": f"Unsupported file type: {ext}. Use .class, .jar, or .zip"})

        return jsonify({
            "filename": safe_name,
            "total_strings": len(all_strings),
            "total_classes": len(class_files),
            "class_files": class_files[:500],
            "strings": all_strings[:5000],  # Limit for response size
            "detections": [
                {
                    "name": d.signature_name,
                    "category": d.category,
                    "severity": d.severity,
                    "description": d.description,
                    "matched_patterns": d.matched_patterns,
                    "confidence": d.confidence,
                }
                for d in all_detections
            ],
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        def cleanup():
            time.sleep(60)
            shutil.rmtree(scan_dir, ignore_errors=True)
        threading.Thread(target=cleanup, daemon=True).start()


# ── Local System Scans ─────────────────────────────────────

@app.route("/api/scan/launchers")
def api_scan_launchers():
    """Detect and scan all Minecraft launchers."""
    try:
        result = full_launcher_scan()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/deleted-files")
def api_scan_deleted():
    """Scan for deleted files (Recycle Bin, Prefetch, Temp, Recent)."""
    try:
        result = scan_deleted_files()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/processes")
def api_scan_processes():
    """Scan running processes for suspicious activity."""
    try:
        result = full_process_scan()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/chrome")
def api_scan_chrome():
    """Scan Chrome browsing history."""
    try:
        result = scan_chrome_history()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/kernel")
def api_scan_kernel():
    """Kernel-level security check."""
    try:
        result = full_kernel_check()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/strings")
def api_scan_strings():
    """Scan common locations for suspicious executables and macros."""
    try:
        hidden = scan_task_manager_binaries()
        return jsonify({
            "suspicious_binaries": hidden,
            "count": len(hidden),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Full Auto Scan ─────────────────────────────────────────

@app.route("/api/scan/full-auto")
def api_full_auto_scan():
    """Run ALL scans automatically."""
    if scan_state["running"]:
        return jsonify({"error": "Scan already in progress", "progress": scan_state["progress"]})

    def run_scan():
        scan_state["running"] = True
        scan_state["progress"] = 0
        scan_state["start_time"] = time.time()
        scan_state["results"] = {}

        try:
            # 1. Launcher Detection
            scan_state["current_task"] = "Detecting Minecraft launchers..."
            scan_state["progress"] = 5
            scan_state["results"]["launchers"] = full_launcher_scan()

            # 2. Scan mods from all detected launchers
            scan_state["current_task"] = "Scanning mods from all launchers..."
            scan_state["progress"] = 15
            all_mod_results = []
            launcher_data = scan_state["results"]["launchers"]
            for launcher in launcher_data.get("launchers", []):
                for mod in launcher.get("mods", []):
                    if mod.get("path") and os.path.isfile(mod["path"]):
                        try:
                            result = inspect_jar(mod["path"])
                            all_mod_results.append(result)
                        except Exception:
                            pass
            scan_state["results"]["mod_scan"] = {
                "total": len(all_mod_results),
                "flagged": sum(1 for r in all_mod_results if r.get("flagged")),
                "results": all_mod_results,
            }
            scan_state["progress"] = 35

            # 3. Process Scan
            scan_state["current_task"] = "Scanning running processes..."
            scan_state["progress"] = 40
            scan_state["results"]["processes"] = full_process_scan()
            scan_state["progress"] = 50

            # 4. Deleted Files
            scan_state["current_task"] = "Scanning deleted files..."
            scan_state["progress"] = 55
            scan_state["results"]["deleted_files"] = scan_deleted_files()
            scan_state["progress"] = 65

            # 5. Chrome History
            scan_state["current_task"] = "Scanning browser history..."
            scan_state["progress"] = 70
            scan_state["results"]["chrome"] = scan_chrome_history()
            scan_state["progress"] = 78

            # 6. Kernel Check
            scan_state["current_task"] = "Running kernel-level checks..."
            scan_state["progress"] = 80
            scan_state["results"]["kernel"] = full_kernel_check()
            scan_state["progress"] = 88

            # 7. String Scanner
            scan_state["current_task"] = "Scanning for hidden tools..."
            scan_state["progress"] = 90
            scan_state["results"]["string_scan"] = {
                "suspicious_binaries": scan_task_manager_binaries(),
            }
            scan_state["progress"] = 95

            # Summary
            scan_state["current_task"] = "Generating report..."
            elapsed = round(time.time() - scan_state["start_time"], 1)

            total_flags = 0
            total_flags += scan_state["results"]["mod_scan"]["flagged"]
            total_flags += len(scan_state["results"]["processes"].get("processes", {}).get("suspicious_processes", []))
            total_flags += len(scan_state["results"]["deleted_files"].get("flagged_deleted_items", []))
            total_flags += len(scan_state["results"]["chrome"].get("suspicious_urls", []))
            total_flags += len(scan_state["results"]["chrome"].get("suspicious_downloads", []))
            total_flags += scan_state["results"]["kernel"].get("drivers", {}).get("suspicious_count", 0)
            total_flags += len(scan_state["results"]["string_scan"].get("suspicious_binaries", []))

            scan_state["results"]["summary"] = {
                "total_flags": total_flags,
                "elapsed_seconds": elapsed,
                "verdict": "CLEAN" if total_flags == 0 else "FLAGGED",
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            scan_state["progress"] = 100
            scan_state["current_task"] = "Scan complete!"

        except Exception as e:
            scan_state["results"]["error"] = str(e)
            scan_state["current_task"] = f"Error: {str(e)}"
        finally:
            scan_state["running"] = False

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({"status": "started", "message": "Full auto scan started"})


@app.route("/api/scan/status")
def api_scan_status():
    """Get current scan progress."""
    return jsonify({
        "running": scan_state["running"],
        "progress": scan_state["progress"],
        "current_task": scan_state["current_task"],
    })


@app.route("/api/scan/results")
def api_scan_results():
    """Get scan results."""
    if scan_state["results"] is None:
        return jsonify({"error": "No scan results available"})
    return jsonify(scan_state["results"])


# ── Text / String Analysis ─────────────────────────────────

@app.route("/api/analyze-text", methods=["POST"])
def api_analyze_text():
    """Analyze pasted text/log content for cheat indicators."""
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data["text"]
    detections = detect_cheats(text, data.get("filename", ""), "user_input")

    return jsonify({
        "detections": [
            {
                "name": d.signature_name,
                "category": d.category,
                "severity": d.severity,
                "description": d.description,
                "matched_patterns": d.matched_patterns,
                "confidence": d.confidence,
            }
            for d in detections
        ],
        "total_flags": len(detections),
        "verdict": "CLEAN" if not detections else "FLAGGED",
    })


# ── Main ───────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("DEBUG", "0") == "1"

    print(f"""
╔══════════════════════════════════════════════════════════╗
║              SS TOOLS NATIVE v2.0.0                      ║
║          Minecraft Screen Share Scanner                  ║
╠══════════════════════════════════════════════════════════╣
║  Web UI:  http://localhost:{port}                         ║
║  API:     http://localhost:{port}/api/info                ║
╚══════════════════════════════════════════════════════════╝
    """)

    app.run(host="0.0.0.0", port=port, debug=debug)
