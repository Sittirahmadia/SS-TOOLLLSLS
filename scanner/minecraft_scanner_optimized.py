"""
Optimized Minecraft Launcher Scanner
- Fast scanning with threading
- No hangs or stuck scans
- Comprehensive mod detection (1.8-1.21.11)
"""

import os
import platform
import json
import threading
import time
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_appdata() -> str:
    """Get Windows AppData path."""
    if platform.system() == "Windows":
        return os.environ.get("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))
    elif platform.system() == "Darwin":
        return os.path.expanduser("~/Library/Application Support")
    else:
        return os.path.expanduser("~")


def get_local_appdata() -> str:
    """Get Windows Local AppData."""
    if platform.system() == "Windows":
        return os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
    elif platform.system() == "Darwin":
        return os.path.expanduser("~/Library/Application Support")
    else:
        return os.path.expanduser("~/.local/share")


def get_home() -> str:
    return os.path.expanduser("~")


# Common launcher paths
LAUNCHER_PATHS = {
    "Minecraft (Official)": [
        os.path.join(get_appdata(), ".minecraft"),
        os.path.join(get_home(), ".minecraft"),
    ],
    "MultiMC": [
        os.path.join(get_local_appdata(), "MultiMC"),
        os.path.join(get_appdata(), "MultiMC"),
    ],
    "Prism Launcher": [
        os.path.join(get_local_appdata(), "PrismLauncher"),
        os.path.join(get_appdata(), "PrismLauncher"),
    ],
    "PolyMC": [
        os.path.join(get_local_appdata(), "PolyMC"),
        os.path.join(get_appdata(), "PolyMC"),
    ],
    "Lunar Client": [
        os.path.join(get_home(), ".lunarclient"),
        os.path.join(get_local_appdata(), "Lunar Client"),
    ],
    "Badlion Client": [
        os.path.join(get_local_appdata(), "Badlion Client"),
        os.path.join(get_appdata(), "Badlion Client"),
    ],
    "Feather Client": [
        os.path.join(get_local_appdata(), "feather"),
        os.path.join(get_home(), ".feather"),
    ],
    "Curseforge": [
        os.path.join(get_local_appdata(), "Curseforge"),
        os.path.join(get_appdata(), "Curseforge"),
    ],
    "Modrinth": [
        os.path.join(get_local_appdata(), "ModrinthApp"),
        os.path.join(get_home(), ".modpack-manager"),
    ],
    "ATLauncher": [
        os.path.join(get_appdata(), "ATLauncher"),
        os.path.join(get_local_appdata(), "ATLauncher"),
    ],
    "GDLauncher": [
        os.path.join(get_local_appdata(), "gdlauncher_next"),
        os.path.join(get_appdata(), "gdlauncher_next"),
    ],
    "TLauncher": [
        os.path.join(get_home(), "TLauncher"),
        os.path.join(get_local_appdata(), "TLauncher"),
    ],
}


def find_launcher_path(launcher_name: str) -> Optional[str]:
    """Find valid launcher path with timeout."""
    paths = LAUNCHER_PATHS.get(launcher_name, [])
    for path in paths:
        try:
            if os.path.isdir(path):
                return path
        except (OSError, PermissionError):
            continue
    return None


def get_mods_from_launcher(launcher_path: str, launcher_name: str, timeout=5) -> List[str]:
    """Get mods from launcher with timeout to prevent hanging."""
    mods = []
    start_time = time.time()

    try:
        if "Official" in launcher_name:
            mods_dir = os.path.join(launcher_path, "mods")
        elif launcher_name in ["MultiMC", "Prism Launcher", "PolyMC"]:
            # Scan instances
            instances_dir = os.path.join(launcher_path, "instances")
            if os.path.isdir(instances_dir):
                for instance in os.listdir(instances_dir):
                    if time.time() - start_time > timeout:
                        break
                    mods_dir = os.path.join(instances_dir, instance, ".minecraft", "mods")
                    if os.path.isdir(mods_dir):
                        for mod in os.listdir(mods_dir):
                            if time.time() - start_time > timeout:
                                break
                            if mod.endswith((".jar", ".zip")):
                                mods.append(os.path.join(mods_dir, mod))
            return mods
        else:
            mods_dir = os.path.join(launcher_path, "mods")

        if os.path.isdir(mods_dir):
            for mod in os.listdir(mods_dir):
                if time.time() - start_time > timeout:
                    break
                if mod.endswith((".jar", ".zip")):
                    mods.append(os.path.join(mods_dir, mod))

    except (OSError, PermissionError):
        pass

    return mods


def full_launcher_scan() -> Dict:
    """Scan all launchers with optimized threading."""
    results = {
        "launchers": [],
        "total_launchers": 0,
        "total_mods": 0,
    }

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}
        for launcher_name in LAUNCHER_PATHS.keys():
            future = executor.submit(find_launcher_path, launcher_name)
            futures[future] = launcher_name

        for future in as_completed(futures):
            launcher_name = futures[future]
            try:
                path = future.result(timeout=5)
                if path:
                    mods = get_mods_from_launcher(path, launcher_name)
                    if mods:
                        results["launchers"].append({
                            "name": launcher_name,
                            "path": path,
                            "mod_count": len(mods),
                            "mods": [{"name": os.path.basename(m), "path": m} for m in mods[:100]]
                        })
                        results["total_mods"] += len(mods)
            except Exception:
                continue

    results["total_launchers"] = len(results["launchers"])
    return results


def scan_logs_for_cheats(launcher_path: str) -> List[Dict]:
    """Scan logs for cheat patterns."""
    findings = []
    logs_dir = os.path.join(launcher_path, "logs")

    if not os.path.isdir(logs_dir):
        return findings

    try:
        for logfile in os.listdir(logs_dir):
            if not logfile.endswith(".log"):
                continue

            try:
                with open(os.path.join(logs_dir, logfile), "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if any(x in content.lower() for x in ["baritone", "schematica", "litematica", "xray"]):
                        findings.append({
                            "file": logfile,
                            "type": "log_cheat_pattern",
                            "risk": "high"
                        })
            except (OSError, PermissionError):
                continue
    except (OSError, PermissionError):
        pass

    return findings


def scan_mods_directory(mod_dir: str, timeout=30) -> List[Dict]:
    """Scan mods directory with timeout."""
    from scanner.jar_inspector import inspect_jar

    results = []
    start_time = time.time()

    try:
        mod_files = [f for f in os.listdir(mod_dir) if f.endswith((".jar", ".zip"))]
        for mod in mod_files:
            if time.time() - start_time > timeout:
                break

            try:
                result = inspect_jar(os.path.join(mod_dir, mod))
                results.append(result)
            except Exception:
                pass
    except (OSError, PermissionError):
        pass

    return results


def get_mod_files(launcher_path: str) -> List[str]:
    """Get all mod files from launcher."""
    mods = []
    mods_dir = os.path.join(launcher_path, "mods")

    if os.path.isdir(mods_dir):
        try:
            for mod in os.listdir(mods_dir):
                if mod.endswith((".jar", ".zip")):
                    mods.append(os.path.join(mods_dir, mod))
        except (OSError, PermissionError):
            pass

    return mods


def scan_custom_folder(folder_path: str) -> List[Dict]:
    """Scan custom folder for mods."""
    from scanner.jar_inspector import inspect_jar

    results = []
    try:
        for file in os.listdir(folder_path):
            if file.endswith((".jar", ".zip")):
                try:
                    result = inspect_jar(os.path.join(folder_path, file))
                    results.append(result)
                except Exception:
                    pass
    except (OSError, PermissionError):
        pass

    return results
