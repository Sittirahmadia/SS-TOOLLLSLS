"""
Minecraft Scanner - Direct Path (NO SEARCHING)
Langsung ke path yang sudah diketahui, tidak perlu cari-cari lagi.
Ultra-fast parallel scanning.
"""

import os
import platform
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DIRECT PATHS - NO SEARCHING NEEDED
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_HOME = os.path.expanduser("~")
_IS_WIN = platform.system() == "Windows"

if _IS_WIN:
    _APPDATA = os.environ.get("APPDATA", os.path.join(_HOME, "AppData", "Roaming"))
    _LOCAL = os.environ.get("LOCALAPPDATA", os.path.join(_HOME, "AppData", "Local"))
else:
    _APPDATA = _HOME
    _LOCAL = os.path.join(_HOME, ".local", "share")

# All known mod directories - go directly, no os.walk searching
DIRECT_MOD_PATHS = [
    # Official Minecraft
    os.path.join(_APPDATA, ".minecraft", "mods"),
    os.path.join(_HOME, ".minecraft", "mods"),

    # MultiMC
    os.path.join(_LOCAL, "MultiMC", "instances"),
    os.path.join(_APPDATA, "MultiMC", "instances"),
    os.path.join(_HOME, ".local", "share", "MultiMC", "instances"),

    # Prism Launcher
    os.path.join(_LOCAL, "PrismLauncher", "instances"),
    os.path.join(_APPDATA, "PrismLauncher", "instances"),
    os.path.join(_HOME, ".local", "share", "PrismLauncher", "instances"),
    os.path.join(_HOME, ".var", "app", "org.prismlauncher.PrismLauncher", "data", "PrismLauncher", "instances"),

    # PolyMC
    os.path.join(_LOCAL, "PolyMC", "instances"),
    os.path.join(_HOME, ".local", "share", "PolyMC", "instances"),

    # GDLauncher
    os.path.join(_LOCAL, "gdlauncher_next", "instances"),
    os.path.join(_APPDATA, "gdlauncher_next", "instances"),

    # ATLauncher
    os.path.join(_LOCAL, "ATLauncher", "instances"),
    os.path.join(_APPDATA, "ATLauncher", "instances"),

    # Technic
    os.path.join(_APPDATA, ".technic", "modpacks"),

    # CurseForge / Overwolf
    os.path.join(_LOCAL, "Overwolf", "curseforge", "minecraft", "Instances"),

    # Lunar Client
    os.path.join(_HOME, ".lunarclient", "offline", "multiver", "mods"),

    # Badlion Client
    os.path.join(_APPDATA, ".minecraft", "BadlionClient", "mods"),

    # Feather Client
    os.path.join(_APPDATA, ".feather", "mods"),

    # Salwyrr Launcher
    os.path.join(_APPDATA, ".minecraft", "SalwyrrMods"),

    # Tlauncher
    os.path.join(_APPDATA, ".tlauncher", "legacy", "Minecraft", "game", "mods"),
    os.path.join(_APPDATA, ".minecraft", "mods"),  # tlauncher often uses .minecraft

    # SKLauncher
    os.path.join(_APPDATA, ".minecraft", "mods"),

    # macOS paths
    os.path.join(_HOME, "Library", "Application Support", "minecraft", "mods"),
    os.path.join(_HOME, "Library", "Application Support", "PrismLauncher", "instances"),
]


def _collect_jars_from_path(path: str) -> List[str]:
    """Collect all .jar files from a path. For instance-based launchers, look 1 level deep."""
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

        # For instance-based launchers: instance_name/mods/*.jar
        # or instance_name/.minecraft/mods/*.jar
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


def collect_all_jars() -> List[str]:
    """Collect ALL .jar mod files from ALL known launcher paths. No searching."""
    all_jars = set()

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_collect_jars_from_path, p): p for p in DIRECT_MOD_PATHS}
        for future in as_completed(futures, timeout=5):
            try:
                jars = future.result()
                all_jars.update(jars)
            except Exception:
                pass

    return list(all_jars)


def full_launcher_scan() -> Dict:
    """Full auto scan - direct paths, no searching, parallel detection."""
    from .cheat_detector import scan_jar_ultra_fast, is_whitelisted_mod

    result = {
        "total_mods": 0,
        "cheats_detected": 0,
        "scans": [],
        "launchers_found": [],
        "risk_summary": "CLEAN"
    }

    # Find which paths exist (for reporting)
    for path in DIRECT_MOD_PATHS:
        if os.path.isdir(path):
            result["launchers_found"].append(path)

    # Collect all JARs
    all_jars = collect_all_jars()
    result["total_mods"] = len(all_jars)

    if not all_jars:
        return result

    # Parallel scan all JARs
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {}
        for jar_path in all_jars[:200]:  # cap at 200 for speed
            if not is_whitelisted_mod(os.path.basename(jar_path)):
                futures[executor.submit(scan_jar_ultra_fast, jar_path)] = jar_path

        for future in as_completed(futures, timeout=10):
            try:
                jar_path = futures[future]
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

    if result["cheats_detected"] > 0:
        result["risk_summary"] = "CRITICAL - CHEATS FOUND"

    return result


def scan_logs_for_cheats(launcher_path: str) -> List[Dict]:
    """Scan launcher logs for cheat traces."""
    from .cheat_detector import detect_cheats_in_text

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
                    content = f.read(500_000)  # cap at 500KB
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


if __name__ == "__main__":
    import json
    result = full_launcher_scan()
    print(json.dumps(result, indent=2, default=str))
