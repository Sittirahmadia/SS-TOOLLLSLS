"""
Minecraft Scanner - Unified (minecraft_scanner + jar_inspector + string_scanner + process_scanner)
All scanning backends merged into single file.
- Direct path Minecraft scanning + fallback search
- JAR inspection with class analysis
- String extraction from binaries
- Process detection with zero false flags
"""

import os
import sys
import re
import struct
import zipfile
import platform
import subprocess
import threading
from typing import List, Dict, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .cheat_detector import (
    detect_cheats, detect_cheats_in_text, is_whitelisted_mod,
    is_whitelisted, verify_mod_authenticity, DetectionResult,
    scan_jar_ultra_fast, LEGITIMATE_MODS
)
from .ghost_detector import scan_for_ghost_clients


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 1: MINECRAFT LAUNCHER SCANNER (direct paths + fallback)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_HOME = os.path.expanduser("~")
_IS_WIN = platform.system() == "Windows"

if _IS_WIN:
    _APPDATA = os.environ.get("APPDATA", os.path.join(_HOME, "AppData", "Roaming"))
    _LOCAL = os.environ.get("LOCALAPPDATA", os.path.join(_HOME, "AppData", "Local"))
else:
    _APPDATA = _HOME
    _LOCAL = os.path.join(_HOME, ".local", "share")

# All known mod directories - go directly, no os.walk
DIRECT_MOD_PATHS = [
    os.path.join(_APPDATA, ".minecraft", "mods"),
    os.path.join(_HOME, ".minecraft", "mods"),
    os.path.join(_LOCAL, "MultiMC", "instances"),
    os.path.join(_APPDATA, "MultiMC", "instances"),
    os.path.join(_HOME, ".local", "share", "MultiMC", "instances"),
    os.path.join(_LOCAL, "PrismLauncher", "instances"),
    os.path.join(_APPDATA, "PrismLauncher", "instances"),
    os.path.join(_HOME, ".local", "share", "PrismLauncher", "instances"),
    os.path.join(_HOME, ".var", "app", "org.prismlauncher.PrismLauncher", "data", "PrismLauncher", "instances"),
    os.path.join(_LOCAL, "PolyMC", "instances"),
    os.path.join(_HOME, ".local", "share", "PolyMC", "instances"),
    os.path.join(_LOCAL, "gdlauncher_next", "instances"),
    os.path.join(_APPDATA, "gdlauncher_next", "instances"),
    os.path.join(_LOCAL, "ATLauncher", "instances"),
    os.path.join(_APPDATA, "ATLauncher", "instances"),
    os.path.join(_APPDATA, ".technic", "modpacks"),
    os.path.join(_LOCAL, "Overwolf", "curseforge", "minecraft", "Instances"),
    os.path.join(_HOME, ".lunarclient", "offline", "multiver", "mods"),
    os.path.join(_APPDATA, ".minecraft", "BadlionClient", "mods"),
    os.path.join(_APPDATA, ".feather", "mods"),
    os.path.join(_APPDATA, ".minecraft", "SalwyrrMods"),
    os.path.join(_APPDATA, ".tlauncher", "legacy", "Minecraft", "game", "mods"),
    os.path.join(_HOME, "Library", "Application Support", "minecraft", "mods"),
    os.path.join(_HOME, "Library", "Application Support", "PrismLauncher", "instances"),
]


def _collect_jars_from_path(path: str) -> List[str]:
    """Collect .jar files from a path. For instance-based launchers, look 1 level deep."""
    jars = []
    if not os.path.isdir(path):
        return jars
    try:
        entries = os.listdir(path)
    except (PermissionError, OSError):
        return jars

    for entry in entries:
        full = os.path.join(path, entry)
        if entry.endswith(".jar") and os.path.isfile(full):
            jars.append(full)
            continue
        if os.path.isdir(full):
            for sub in ["mods", os.path.join(".minecraft", "mods"), os.path.join("minecraft", "mods")]:
                mods_dir = os.path.join(full, sub)
                if os.path.isdir(mods_dir):
                    try:
                        for f in os.listdir(mods_dir):
                            if f.endswith(".jar"):
                                jars.append(os.path.join(mods_dir, f))
                    except (PermissionError, OSError):
                        pass
    return jars


def _fallback_search_jars() -> List[str]:
    """Fallback: search common directories for .minecraft/mods if direct paths fail."""
    jars = []
    search_roots = []

    if _IS_WIN:
        for drive in "CDEFG":
            p = f"{drive}:\\Users"
            if os.path.isdir(p):
                search_roots.append(p)
    else:
        search_roots.append("/home")
        search_roots.append(_HOME)

    for root in search_roots:
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                depth = dirpath.replace(root, "").count(os.sep)
                if depth > 4:
                    dirnames[:] = []
                    continue
                basename = os.path.basename(dirpath)
                if basename == "mods":
                    parent = os.path.basename(os.path.dirname(dirpath))
                    if parent in (".minecraft", "minecraft") or "instance" in os.path.dirname(dirpath).lower():
                        for f in filenames:
                            if f.endswith(".jar"):
                                jars.append(os.path.join(dirpath, f))
                # Don't descend into large irrelevant dirs
                dirnames[:] = [d for d in dirnames if d not in (
                    "node_modules", ".git", "Windows", "Program Files",
                    "Program Files (x86)", "$Recycle.Bin", "System Volume Information"
                )]
                if len(jars) >= 200:
                    return jars
        except (PermissionError, OSError):
            continue
    return jars


def collect_all_jars() -> List[str]:
    """Collect ALL .jar mod files. Direct paths first, fallback search if none found."""
    all_jars = set()

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_collect_jars_from_path, p): p for p in DIRECT_MOD_PATHS}
        for future in as_completed(futures, timeout=5):
            try:
                jars = future.result()
                all_jars.update(jars)
            except Exception:
                pass

    # Fallback: if direct paths found nothing, search
    if not all_jars:
        all_jars.update(_fallback_search_jars())

    return list(all_jars)


def full_launcher_scan() -> Dict:
    """Full auto scan - direct paths + fallback + ghost detection. Returns complete report."""
    result = {
        "total_mods": 0,
        "cheats_detected": 0,
        "ghost_clients_detected": 0,
        "scans": [],
        "ghost_scans": [],
        "launchers_found": [],
        "risk_summary": "CLEAN",
        "used_fallback": False,
    }

    for path in DIRECT_MOD_PATHS:
        if os.path.isdir(path):
            result["launchers_found"].append(path)

    all_jars = collect_all_jars()
    result["total_mods"] = len(all_jars)

    if not all_jars and not result["launchers_found"]:
        result["used_fallback"] = True

    if not all_jars:
        return result

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures_cheat = {}
        futures_ghost = {}

        for jar_path in all_jars[:200]:
            basename = os.path.basename(jar_path)
            if not is_whitelisted_mod(basename):
                futures_cheat[executor.submit(scan_jar_ultra_fast, jar_path)] = jar_path
                futures_ghost[executor.submit(scan_for_ghost_clients, jar_path)] = jar_path

        for future in as_completed(futures_cheat, timeout=10):
            try:
                jar_path = futures_cheat[future]
                scan_result = future.result()
                if scan_result.get("is_cheat"):
                    result["cheats_detected"] += 1
                    result["scans"].append({
                        "file": os.path.basename(jar_path),
                        "path": jar_path,
                        "risk_level": scan_result.get("risk_level", "UNKNOWN"),
                        "confidence": scan_result.get("confidence", 0),
                        "categories": scan_result.get("categories", []),
                    })
            except Exception:
                pass

        for future in as_completed(futures_ghost, timeout=10):
            try:
                jar_path = futures_ghost[future]
                ghost_result = future.result()
                if ghost_result.get("ghost_clients"):
                    result["ghost_clients_detected"] += 1
                    result["ghost_scans"].append({
                        "file": os.path.basename(jar_path),
                        "ghosts": ghost_result["ghost_clients"],
                        "confidence": ghost_result.get("confidence", 0),
                    })
            except Exception:
                pass

    if result["ghost_clients_detected"] > 0:
        result["risk_summary"] = "CRITICAL - GHOST CLIENTS FOUND"
    elif result["cheats_detected"] > 0:
        result["risk_summary"] = "CRITICAL - CHEATS FOUND"

    return result


def scan_logs_for_cheats(launcher_path: str) -> List[Dict]:
    """Scan launcher logs for cheat traces."""
    findings = []
    log_locations = [
        os.path.join(launcher_path, "logs", "latest.log"),
        os.path.join(launcher_path, "logs", "debug.log"),
        os.path.join(launcher_path, "crash-reports"),
    ]
    for log_path in log_locations:
        if os.path.isfile(log_path):
            try:
                with open(log_path, "r", errors="ignore") as f:
                    content = f.read(500_000)
                detected = detect_cheats_in_text(content, os.path.basename(log_path))
                if detected:
                    findings.append({
                        "log_file": log_path,
                        "detections": [{"name": d.name, "category": d.category, "severity": d.severity} for d in detected],
                    })
            except Exception:
                pass
        elif os.path.isdir(log_path):
            try:
                for f in os.listdir(log_path)[:20]:
                    crash_file = os.path.join(log_path, f)
                    if os.path.isfile(crash_file):
                        try:
                            with open(crash_file, "r", errors="ignore") as fh:
                                content = fh.read(200_000)
                            detected = detect_cheats_in_text(content, f)
                            if detected:
                                findings.append({
                                    "log_file": crash_file,
                                    "detections": [{"name": d.name, "category": d.category, "severity": d.severity} for d in detected],
                                })
                        except Exception:
                            pass
            except Exception:
                pass
    return findings


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 2: JAR INSPECTOR (view contents + deep analysis)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def read_jar_entries(jar_path: str) -> Dict:
    """Read a JAR/ZIP file and return its structure."""
    result = {
        "path": jar_path,
        "filename": os.path.basename(jar_path),
        "size_mb": round(os.path.getsize(jar_path) / (1024 * 1024), 2),
        "class_files": [], "text_files": [], "resource_files": [],
        "manifest": None, "mod_info": None, "fabric_mod_json": None,
        "entries_count": 0, "error": None,
    }
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            result["entries_count"] = len(zf.namelist())
            for entry in zf.namelist():
                el = entry.lower()
                if el.endswith(".class"):
                    result["class_files"].append(entry)
                elif el.endswith((".txt", ".cfg", ".conf", ".properties", ".json", ".toml", ".yml", ".yaml", ".xml", ".mcmeta", ".lang")):
                    result["text_files"].append(entry)
                else:
                    result["resource_files"].append(entry)
                if entry == "META-INF/MANIFEST.MF":
                    try: result["manifest"] = zf.read(entry).decode("utf-8", errors="replace")
                    except: pass
                if el in ("mcmod.info", "mods.toml", "pack.mcmeta"):
                    try: result["mod_info"] = zf.read(entry).decode("utf-8", errors="replace")
                    except: pass
                if entry == "fabric.mod.json":
                    try: result["fabric_mod_json"] = zf.read(entry).decode("utf-8", errors="replace")
                    except: pass
    except zipfile.BadZipFile:
        result["error"] = "Invalid or corrupted JAR/ZIP file"
    except Exception as e:
        result["error"] = str(e)
    return result


def extract_strings_from_class(class_bytes: bytes) -> List[str]:
    """Extract UTF-8 string constants from a Java .class file's constant pool."""
    strings = []
    try:
        if len(class_bytes) < 10:
            return strings
        magic = struct.unpack(">I", class_bytes[:4])[0]
        if magic != 0xCAFEBABE:
            return strings
        offset = 8
        cp_count = struct.unpack(">H", class_bytes[offset:offset+2])[0]
        offset += 2
        i = 1
        while i < cp_count and offset < len(class_bytes):
            tag = class_bytes[offset]
            offset += 1
            if tag == 1:
                if offset + 2 > len(class_bytes): break
                length = struct.unpack(">H", class_bytes[offset:offset+2])[0]
                offset += 2
                if offset + length > len(class_bytes): break
                try:
                    s = class_bytes[offset:offset+length].decode("utf-8", errors="replace")
                    if len(s) >= 3 and not all(c in " \t\n\r" for c in s):
                        strings.append(s)
                except: pass
                offset += length
            elif tag in (7, 8, 16, 19, 20): offset += 2
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18): offset += 4
            elif tag in (5, 6): offset += 8; i += 1
            elif tag == 15: offset += 3
            else: break
            i += 1
    except: pass
    return strings


def inspect_jar(jar_path: str) -> Dict:
    """Full JAR inspection: structure + class strings + cheat detection + ghost detection + authenticity."""
    filename = os.path.basename(jar_path)
    claims_whitelisted = is_whitelisted(filename)
    entries = read_jar_entries(jar_path)

    if entries.get("error"):
        return {"path": jar_path, "filename": filename, "error": entries["error"], "detections": []}

    all_detections: List[DetectionResult] = []
    scanned_classes = 0
    all_strings_combined = []

    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            for class_file in entries["class_files"]:
                try:
                    class_bytes = zf.read(class_file)
                    strings = extract_strings_from_class(class_bytes)
                    scanned_classes += 1
                    content = " ".join(strings) + " " + class_file
                    all_strings_combined.extend(strings)
                    detections = detect_cheats(content, class_file, f"{jar_path}!/{class_file}")
                    all_detections.extend(detections)
                except: continue
            for text_file in entries["text_files"]:
                try:
                    text_content = zf.read(text_file).decode("utf-8", errors="replace")
                    detections = detect_cheats(text_content, text_file, f"{jar_path}!/{text_file}")
                    all_detections.extend(detections)
                except: continue
            if entries["manifest"]:
                all_detections.extend(detect_cheats(entries["manifest"], "MANIFEST.MF", f"{jar_path}!/META-INF/MANIFEST.MF"))
            for meta_field in ["mod_info", "fabric_mod_json"]:
                if entries[meta_field]:
                    all_detections.extend(detect_cheats(entries[meta_field], meta_field, f"{jar_path}!/{meta_field}"))
    except Exception as e:
        return {"path": jar_path, "filename": filename, "error": str(e), "detections": []}

    name_detections = detect_cheats("", filename, jar_path)
    all_detections.extend(name_detections)
    combined = " ".join(all_strings_combined)
    combined_detections = detect_cheats(combined, filename, jar_path)
    existing_sigs = {d.signature_name for d in all_detections}
    for d in combined_detections:
        if d.signature_name not in existing_sigs:
            all_detections.append(d)
            existing_sigs.add(d.signature_name)

    seen = set()
    unique_detections = []
    for d in all_detections:
        key = (d.signature_name, d.file_path)
        if key not in seen:
            seen.add(key)
            unique_detections.append(d)

    authenticity = verify_mod_authenticity(filename, entries["class_files"])
    is_disguised = False
    if claims_whitelisted and not authenticity["is_authentic"]:
        is_disguised = True
        unique_detections.insert(0, DetectionResult(
            flagged=True, signature_name="Disguised Cheat (Fake Whitelisted Mod)",
            category="Evasion", severity="critical",
            description=f"JAR named like '{authenticity['claimed_mod']}' but has WRONG package structure.",
            matched_patterns=[f"fake_name:{authenticity['claimed_mod']}"],
            match_count=1, file_path=jar_path, confidence=0.95,
        ))

    # Ghost detection
    ghost_result = scan_for_ghost_clients(jar_path, max_workers=4)

    flagged = len(unique_detections) > 0 or ghost_result.get("ghost_clients")
    max_severity = "none"
    if unique_detections:
        sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_severity = max(unique_detections, key=lambda d: sev_map.get(d.severity, 0)).severity
    if ghost_result.get("ghost_clients"):
        max_severity = "critical"

    verified_whitelisted = claims_whitelisted and authenticity["is_authentic"] and not flagged

    return {
        "path": jar_path, "filename": filename,
        "whitelisted": verified_whitelisted,
        "safe": verified_whitelisted or not flagged,
        "flagged": flagged, "is_disguised": is_disguised,
        "max_severity": max_severity,
        "ghost_clients": ghost_result.get("ghost_clients", []),
        "ghost_confidence": ghost_result.get("confidence", 0),
        "authenticity": {
            "claimed_mod": authenticity["claimed_mod"],
            "is_authentic": authenticity["is_authentic"],
            "expected_packages": authenticity["expected_packages"],
            "found_matching": authenticity["found_matching"],
            "confidence": authenticity["confidence"],
        } if claims_whitelisted else None,
        "class_count": len(entries["class_files"]),
        "text_count": len(entries["text_files"]),
        "resource_count": len(entries["resource_files"]),
        "scanned_classes": scanned_classes,
        "total_entries": entries["entries_count"],
        "size_mb": entries["size_mb"],
        "class_files": entries["class_files"][:200],
        "detections": [
            {"name": d.signature_name, "category": d.category, "severity": d.severity,
             "description": d.description, "matched_patterns": d.matched_patterns,
             "match_count": d.match_count, "file": d.file_path, "confidence": d.confidence}
            for d in unique_detections
        ],
        "manifest": entries["manifest"],
        "mod_info": entries["mod_info"],
        "fabric_mod_json": entries["fabric_mod_json"],
    }


def scan_mods_directory(mods_dir: str) -> List[Dict]:
    """Scan an entire mods directory."""
    results = []
    if not os.path.isdir(mods_dir):
        return results
    for root, dirs, files in os.walk(mods_dir):
        for f in files:
            if f.lower().endswith((".jar", ".zip")):
                fpath = os.path.join(root, f)
                try:
                    results.append(inspect_jar(fpath))
                except Exception as e:
                    results.append({"path": fpath, "filename": f, "error": str(e), "detections": []})
    return results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 3: STRING SCANNER (binary string extraction + pattern matching)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

INJECTOR_PATTERNS = [
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtCreateThreadEx", "RtlCreateUserThread",
    "VirtualAllocEx", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "NtWriteVirtualMemory", "NtReadVirtualMemory",
    "SetWindowsHookEx", "QueueUserAPC",
    "OpenProcess", "NtOpenProcess",
    "NtSuspendProcess", "NtResumeProcess",
    "EnumProcessModules", "CreateToolhelp32Snapshot",
]

MACRO_PATTERNS = [
    "198macro", "198_macro", "zenithmacro", "zenith_macro",
    "opmacro", "op_macro", "crystalmacro", "crystal_macro",
    "cpvpmacro", "anchorbot",
    "hotkey_toggle", "macro_enabled", "click_delay", "click_speed",
    "auto_click", "auto_place", "crystal_speed", "crystal_delay",
    "swap_delay", "switch_delay", "anchor_delay", "bed_delay",
]

CHEAT_STRING_PATTERNS = [
    "ModuleCategory", "ModuleManager", "HackManager",
    "CheatManager", "FeatureManager",
    "MODULE_COMBAT", "MODULE_MOVEMENT", "MODULE_RENDER",
    "MODULE_PLAYER", "MODULE_WORLD", "MODULE_MISC",
    "onEnable", "onDisable", "isEnabled",
    "hackList", "enabledHacks",
    "PacketListener", "PacketHandler",
    "sendPacketDirect", "cancelPacket", "spoofPacket",
    "bypassCheck", "anticheatBypass", "disableAC",
    "watchdogBypass", "sentinelBypass", "vulcanBypass",
    "grimBypass", "nocomBypass",
]


def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """Extract printable ASCII and UTF-16 strings from binary data."""
    strings = []
    ascii_pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    for match in ascii_pattern.finditer(data):
        try: strings.append(match.group().decode('ascii'))
        except: pass
    utf16_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % min_length)
    for match in utf16_pattern.finditer(data):
        try: strings.append(match.group().decode('utf-16-le'))
        except: pass
    return strings


def scan_file_strings(file_path: str) -> Dict:
    """Scan a single file for suspicious strings."""
    result = {
        "path": file_path, "filename": os.path.basename(file_path), "size_mb": 0,
        "injector_matches": [], "macro_matches": [], "cheat_matches": [],
        "cheat_detections": [], "error": None,
    }
    try:
        stat = os.stat(file_path)
        result["size_mb"] = round(stat.st_size / (1024 * 1024), 2)
        if stat.st_size > 100 * 1024 * 1024:
            result["error"] = "File too large (>100MB)"
            return result
        with open(file_path, "rb") as f:
            data = f.read()
        strings = extract_strings(data)
        all_text = " ".join(strings).lower()
        for p in INJECTOR_PATTERNS:
            if p.lower() in all_text: result["injector_matches"].append(p)
        for p in MACRO_PATTERNS:
            if p.lower() in all_text: result["macro_matches"].append(p)
        for p in CHEAT_STRING_PATTERNS:
            if p.lower() in all_text: result["cheat_matches"].append(p)
        detections = detect_cheats(all_text, os.path.basename(file_path), file_path)
        result["cheat_detections"] = [
            {"name": d.signature_name, "category": d.category, "severity": d.severity,
             "confidence": d.confidence, "matched": d.matched_patterns}
            for d in detections
        ]
    except PermissionError:
        result["error"] = "Permission denied"
    except Exception as e:
        result["error"] = str(e)
    return result


def scan_directory_for_strings(directory: str, extensions: Set[str] = None, max_depth: int = 3) -> List[Dict]:
    """Scan a directory tree for suspicious files."""
    if extensions is None:
        extensions = {".exe", ".dll", ".jar", ".zip", ".bat", ".cmd", ".ps1", ".sys"}
    results = []
    for root, dirs, files in os.walk(directory):
        depth = root.replace(directory, "").count(os.sep)
        if depth > max_depth:
            continue
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in extensions:
                fpath = os.path.join(root, f)
                result = scan_file_strings(fpath)
                if result["injector_matches"] or result["macro_matches"] or result["cheat_matches"] or result["cheat_detections"]:
                    results.append(result)
    return results


def scan_task_manager_binaries() -> List[Dict]:
    """Scan for suspicious executables hidden from task manager."""
    results = []
    suspicious_dirs = []
    if os.name == "nt":
        home = os.path.expanduser("~")
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        suspicious_dirs = [
            os.path.join(localappdata, "Temp"), os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"), os.path.join(home, "Documents"),
            appdata, localappdata,
        ]
    else:
        home = os.path.expanduser("~")
        suspicious_dirs = [os.path.join(home, "Downloads"), os.path.join(home, "Desktop"), "/tmp"]

    known_names = ["198macro", "zenithmacro", "crystalmacro", "injector", "autoclicker",
                   "processhacker", "cheatengine", "extremeinjector", "xenos"]

    for d in suspicious_dirs:
        if not os.path.isdir(d): continue
        try:
            for f in os.listdir(d):
                fpath = os.path.join(d, f)
                if not os.path.isfile(fpath): continue
                ext = os.path.splitext(f)[1].lower()
                name_lower = f.lower()
                suspicious = False
                reason = ""
                for kn in known_names:
                    if kn in name_lower:
                        suspicious = True
                        reason = f"Known tool: {kn}"
                        break
                if ext in (".exe", ".dll") and not suspicious:
                    if len(f.replace(ext, "")) > 20 and all(c.isalnum() for c in f.replace(ext, "")):
                        suspicious = True
                        reason = "Randomly named executable"
                if suspicious:
                    results.append({"path": fpath, "filename": f, "reason": reason,
                                    "size_mb": round(os.path.getsize(fpath) / (1024 * 1024), 2)})
        except: continue
    return results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 4: PROCESS SCANNER (zero false flags)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHITELIST_PROCESSES = {
    "svchost.exe", "dwm.exe", "csrss.exe", "lsass.exe", "services.exe",
    "spoolsv.exe", "rundll32.exe", "winlogon.exe", "explorer.exe",
    "java.exe", "javaw.exe", "minecraft.exe", "javaws.exe",
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
    "steam.exe", "discord.exe", "spotify.exe", "slack.exe",
    "obs64.exe", "obs32.exe", "vlc.exe", "notepad.exe",
    "TLauncher.exe", "MCLauncher.exe", "PolyMC.exe", "PrismLauncher.exe",
    "MsMpEng.exe", "NisSrv.exe",
}

MALICIOUS_PROCESSES = {
    "cheatengine": {"category": "cheat_engine", "risk": "CRITICAL"},
    "CE.exe": {"category": "cheat_engine", "risk": "CRITICAL"},
    "injector": {"category": "injector", "risk": "CRITICAL"},
    "artmoney": {"category": "memory_hacker", "risk": "CRITICAL"},
    "WPE PRO": {"category": "packet_editor", "risk": "CRITICAL"},
    "keylogger": {"category": "keylogger", "risk": "CRITICAL"},
    "xmrig": {"category": "crypto_miner", "risk": "HIGH"},
    "claymore": {"category": "crypto_miner", "risk": "HIGH"},
}

BOT_TOOLS = {
    "autohotkey": {"category": "macro_tool", "risk": "MEDIUM"},
    "ahk": {"category": "macro_tool", "risk": "MEDIUM"},
    "macro": {"category": "macro_tool", "risk": "MEDIUM"},
}


def get_running_processes() -> List[Dict]:
    """Get all running processes."""
    processes = []
    try:
        if _IS_WIN:
            result = subprocess.run(["tasklist", "/v"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split("\n")[3:]:
                if not line.strip(): continue
                parts = line.split()
                if len(parts) >= 2:
                    try: processes.append({"name": parts[0], "pid": int(parts[1]), "platform": "Windows"})
                    except ValueError: pass
        else:
            result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split("\n")[1:]:
                if not line.strip(): continue
                parts = line.split()
                if len(parts) >= 11:
                    try:
                        cmd = " ".join(parts[10:])
                        processes.append({"name": os.path.basename(cmd.split()[0]) if cmd else "", "cmd": cmd, "pid": int(parts[1]), "platform": platform.system()})
                    except: pass
    except: pass
    return processes


def analyze_process(process: Dict) -> Dict:
    """Analyze a single process."""
    name_lower = process["name"].lower()
    cmd_lower = process.get("cmd", "").lower()
    if process["name"] in WHITELIST_PROCESSES:
        return {"name": process["name"], "pid": process["pid"], "status": "whitelisted", "risk": "NONE"}
    for mal_name, info in MALICIOUS_PROCESSES.items():
        if mal_name.lower() in name_lower or mal_name.lower() in cmd_lower:
            return {"name": process["name"], "pid": process["pid"], "status": "suspicious",
                    "category": info["category"], "risk": info["risk"], "cmd": process.get("cmd", "")}
    for bot_name, info in BOT_TOOLS.items():
        if bot_name.lower() in name_lower or bot_name.lower() in cmd_lower:
            return {"name": process["name"], "pid": process["pid"], "status": "potential_bot",
                    "category": info["category"], "risk": info["risk"], "cmd": process.get("cmd", "")}
    return {"name": process["name"], "pid": process["pid"], "status": "unknown", "risk": "NONE"}


def full_process_scan() -> Dict:
    """Full process scan with threading."""
    results = {
        "total_processes": 0, "suspicious_processes": [], "bot_tools": [], "whitelisted": [],
        "summary": {"risk_level": "NONE", "suspicious_count": 0, "bot_count": 0}
    }
    try:
        processes = get_running_processes()
        results["total_processes"] = len(processes)
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(analyze_process, p): p for p in processes}
            for future in as_completed(futures):
                try:
                    a = future.result(timeout=5)
                    if a["status"] == "suspicious": results["suspicious_processes"].append(a)
                    elif a["status"] == "potential_bot": results["bot_tools"].append(a)
                    elif a["status"] == "whitelisted": results["whitelisted"].append(a)
                except: continue
    except Exception as e:
        results["error"] = str(e)
    results["summary"]["suspicious_count"] = len(results["suspicious_processes"])
    results["summary"]["bot_count"] = len(results["bot_tools"])
    if results["suspicious_processes"]: results["summary"]["risk_level"] = "CRITICAL"
    elif results["bot_tools"]: results["summary"]["risk_level"] = "MEDIUM"
    return results


def get_process_details(pid: int) -> Dict:
    try:
        if _IS_WIN:
            result = subprocess.run(["wmic", "process", "where", f"ProcessId={pid}", "get", "ExecutablePath"],
                                    capture_output=True, text=True, timeout=5)
            return {"path": result.stdout.strip()}
    except: pass
    return {"error": "Could not get process details"}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 5: FULL AUTO SCAN (everything combined)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def full_auto_scan() -> Dict:
    """COMPLETE auto scan: Minecraft + Ghost + JAR + Processes + Strings."""
    report = {
        "minecraft": full_launcher_scan(),
        "processes": full_process_scan(),
        "suspicious_binaries": scan_task_manager_binaries(),
        "overall_risk": "CLEAN",
        "total_threats": 0,
    }

    threats = 0
    if report["minecraft"]["cheats_detected"] > 0:
        threats += report["minecraft"]["cheats_detected"]
    if report["minecraft"]["ghost_clients_detected"] > 0:
        threats += report["minecraft"]["ghost_clients_detected"]
    if report["processes"]["summary"]["suspicious_count"] > 0:
        threats += report["processes"]["summary"]["suspicious_count"]
    threats += len(report["suspicious_binaries"])

    report["total_threats"] = threats
    if threats > 0:
        report["overall_risk"] = "CRITICAL - THREATS DETECTED"

    return report


if __name__ == "__main__":
    import json
    result = full_auto_scan()
    print(json.dumps(result, indent=2, default=str))
