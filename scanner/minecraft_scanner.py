"""
Minecraft Launcher Auto-Detection
Detects ALL major Minecraft launchers and their mod directories.
Supports: Official, MultiMC, Prism, Lunar, Badlion, Feather, Curseforge,
          Modrinth, ATLauncher, GDLauncher, TLauncher, Salwyrr, PolyMC, etc.
"""

import os
import platform
import json
import glob
from typing import List, Dict, Optional


def get_appdata() -> str:
    """Get Windows AppData path (or equivalent)."""
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


LAUNCHER_CONFIGS = [
    # Official Minecraft Launcher
    {
        "name": "Minecraft (Official)",
        "paths": [
            os.path.join(get_appdata(), ".minecraft"),
            os.path.join(get_home(), ".minecraft"),
            os.path.join(get_appdata(), ".minecraft"),
        ],
        "mods_subdir": "mods",
        "versions_subdir": "versions",
        "logs_subdir": "logs",
        "config_files": ["launcher_profiles.json", "options.txt"],
    },
    # MultiMC / PolyMC / Prism Launcher (instance-based)
    {
        "name": "MultiMC",
        "paths": [
            os.path.join(get_local_appdata(), "MultiMC"),
            os.path.join(get_appdata(), "MultiMC"),
            os.path.join(get_home(), "MultiMC"),
        ],
        "instances_dir": "instances",
        "mods_subdir": ".minecraft/mods",
        "versions_subdir": ".minecraft/versions",
        "logs_subdir": ".minecraft/logs",
    },
    {
        "name": "Prism Launcher",
        "paths": [
            os.path.join(get_local_appdata(), "PrismLauncher"),
            os.path.join(get_appdata(), "PrismLauncher"),
            os.path.join(get_home(), ".local/share/PrismLauncher"),
        ],
        "instances_dir": "instances",
        "mods_subdir": ".minecraft/mods",
        "versions_subdir": ".minecraft/versions",
        "logs_subdir": ".minecraft/logs",
    },
    {
        "name": "PolyMC",
        "paths": [
            os.path.join(get_local_appdata(), "PolyMC"),
            os.path.join(get_appdata(), "PolyMC"),
            os.path.join(get_home(), ".local/share/PolyMC"),
        ],
        "instances_dir": "instances",
        "mods_subdir": ".minecraft/mods",
        "versions_subdir": ".minecraft/versions",
        "logs_subdir": ".minecraft/logs",
    },
    # Lunar Client
    {
        "name": "Lunar Client",
        "paths": [
            os.path.join(get_home(), ".lunarclient"),
            os.path.join(get_appdata(), ".lunarclient"),
            os.path.join(get_local_appdata(), "Lunar Client"),
        ],
        "mods_subdir": "mods",
        "versions_subdir": "offline/multiver",
        "logs_subdir": "logs",
    },
    # Badlion Client
    {
        "name": "Badlion Client",
        "paths": [
            os.path.join(get_appdata(), ".badlion"),
            os.path.join(get_home(), ".badlion"),
            os.path.join(get_local_appdata(), "Badlion Client"),
        ],
        "mods_subdir": "mods",
        "logs_subdir": "logs",
    },
    # Feather Client
    {
        "name": "Feather Client",
        "paths": [
            os.path.join(get_appdata(), ".feather"),
            os.path.join(get_home(), ".feather"),
            os.path.join(get_local_appdata(), "Feather Client"),
        ],
        "mods_subdir": "mods",
        "logs_subdir": "logs",
    },
    # CurseForge / Overwolf
    {
        "name": "CurseForge",
        "paths": [
            os.path.join(get_appdata(), "curseforge", "minecraft"),
            os.path.join(get_home(), "curseforge", "minecraft"),
            os.path.join(get_local_appdata(), "CurseForge", "Minecraft"),
        ],
        "instances_dir": "Instances",
        "mods_subdir": "mods",
        "logs_subdir": "logs",
    },
    # Modrinth App
    {
        "name": "Modrinth",
        "paths": [
            os.path.join(get_appdata(), "ModrinthApp", "profiles"),
            os.path.join(get_appdata(), "com.modrinth.theseus", "profiles"),
            os.path.join(get_local_appdata(), "ModrinthApp"),
        ],
        "instances_dir": ".",
        "mods_subdir": "mods",
        "logs_subdir": "logs",
    },
    # ATLauncher
    {
        "name": "ATLauncher",
        "paths": [
            os.path.join(get_appdata(), "ATLauncher"),
            os.path.join(get_local_appdata(), "ATLauncher"),
            os.path.join(get_home(), "ATLauncher"),
        ],
        "instances_dir": "instances",
        "mods_subdir": "mods",
        "logs_subdir": "logs",
    },
    # GDLauncher
    {
        "name": "GDLauncher",
        "paths": [
            os.path.join(get_appdata(), "gdlauncher_next", "instances"),
            os.path.join(get_local_appdata(), "GDLauncher"),
            os.path.join(get_appdata(), "gdlauncher"),
        ],
        "instances_dir": ".",
        "mods_subdir": "mods",
        "logs_subdir": "logs",
    },
    # TLauncher
    {
        "name": "TLauncher",
        "paths": [
            os.path.join(get_appdata(), ".tlauncher"),
            os.path.join(get_home(), ".tlauncher"),
            os.path.join(get_appdata(), ".minecraft"),  # TLauncher often uses .minecraft
        ],
        "mods_subdir": "mods",
        "versions_subdir": "versions",
        "logs_subdir": "logs",
    },
    # Salwyrr Launcher
    {
        "name": "Salwyrr Launcher",
        "paths": [
            os.path.join(get_appdata(), ".salwyrr"),
            os.path.join(get_local_appdata(), "Salwyrr Launcher"),
        ],
        "mods_subdir": "mods",
        "logs_subdir": "logs",
    },
    # Technic Launcher
    {
        "name": "Technic Launcher",
        "paths": [
            os.path.join(get_appdata(), ".technic"),
            os.path.join(get_home(), ".technic"),
        ],
        "instances_dir": "modpacks",
        "mods_subdir": "mods",
        "logs_subdir": "logs",
    },
    # Forge Installer (standalone)
    {
        "name": "Forge (in .minecraft)",
        "paths": [
            os.path.join(get_appdata(), ".minecraft"),
        ],
        "mods_subdir": "mods",
        "versions_subdir": "versions",
        "logs_subdir": "logs",
    },
    # Fabric (standalone)
    {
        "name": "Fabric (in .minecraft)",
        "paths": [
            os.path.join(get_appdata(), ".minecraft"),
        ],
        "mods_subdir": "mods",
        "versions_subdir": "versions",
        "logs_subdir": "logs",
    },
    # SKLauncher
    {
        "name": "SKLauncher",
        "paths": [
            os.path.join(get_appdata(), "SKLauncher"),
            os.path.join(get_local_appdata(), "SKLauncher"),
        ],
        "mods_subdir": "mods",
        "logs_subdir": "logs",
    },
]


def detect_launchers() -> List[Dict]:
    """Detect all installed Minecraft launchers."""
    found = []
    seen_paths = set()

    for config in LAUNCHER_CONFIGS:
        for base_path in config["paths"]:
            if not os.path.isdir(base_path):
                continue

            real = os.path.realpath(base_path)
            if real in seen_paths:
                continue
            seen_paths.add(real)

            launcher = {
                "name": config["name"],
                "path": base_path,
                "mods_dirs": [],
                "versions_dirs": [],
                "logs_dirs": [],
                "instances": [],
            }

            # Check for instance-based launchers
            instances_dir_name = config.get("instances_dir")
            if instances_dir_name:
                instances_path = os.path.join(base_path, instances_dir_name)
                if os.path.isdir(instances_path):
                    for instance_name in os.listdir(instances_path):
                        instance_path = os.path.join(instances_path, instance_name)
                        if os.path.isdir(instance_path):
                            launcher["instances"].append(instance_name)

                            # Check mods in instance
                            mods_sub = config.get("mods_subdir", "mods")
                            mods_path = os.path.join(instance_path, mods_sub)
                            if os.path.isdir(mods_path):
                                launcher["mods_dirs"].append(mods_path)

                            # Check versions in instance
                            ver_sub = config.get("versions_subdir")
                            if ver_sub:
                                ver_path = os.path.join(instance_path, ver_sub)
                                if os.path.isdir(ver_path):
                                    launcher["versions_dirs"].append(ver_path)

                            # Check logs in instance
                            logs_sub = config.get("logs_subdir", "logs")
                            logs_path = os.path.join(instance_path, logs_sub)
                            if os.path.isdir(logs_path):
                                launcher["logs_dirs"].append(logs_path)

            # Direct mods/versions/logs
            mods_sub = config.get("mods_subdir", "mods")
            direct_mods = os.path.join(base_path, mods_sub)
            if os.path.isdir(direct_mods) and direct_mods not in launcher["mods_dirs"]:
                launcher["mods_dirs"].append(direct_mods)

            ver_sub = config.get("versions_subdir")
            if ver_sub:
                direct_ver = os.path.join(base_path, ver_sub)
                if os.path.isdir(direct_ver):
                    launcher["versions_dirs"].append(direct_ver)

            logs_sub = config.get("logs_subdir", "logs")
            direct_logs = os.path.join(base_path, logs_sub)
            if os.path.isdir(direct_logs):
                launcher["logs_dirs"].append(direct_logs)

            found.append(launcher)

    return found


def get_mod_files(mods_dir: str) -> List[Dict]:
    """List all mod files in a directory."""
    mods = []
    if not os.path.isdir(mods_dir):
        return mods

    for f in os.listdir(mods_dir):
        fpath = os.path.join(mods_dir, f)
        if os.path.isfile(fpath) and f.lower().endswith((".jar", ".zip", ".litemod")):
            mods.append({
                "name": f,
                "path": fpath,
                "size_mb": round(os.path.getsize(fpath) / (1024 * 1024), 2),
            })

    return mods


def get_versions(versions_dir: str) -> List[Dict]:
    """List installed Minecraft versions."""
    versions = []
    if not os.path.isdir(versions_dir):
        return versions

    for v in os.listdir(versions_dir):
        vpath = os.path.join(versions_dir, v)
        if os.path.isdir(vpath):
            # Check for version JSON
            vjson = os.path.join(vpath, f"{v}.json")
            version_info = {"name": v, "path": vpath}

            if os.path.isfile(vjson):
                try:
                    with open(vjson, "r") as f:
                        data = json.load(f)
                    version_info["id"] = data.get("id", v)
                    version_info["type"] = data.get("type", "unknown")
                    version_info["inheritsFrom"] = data.get("inheritsFrom")
                except Exception:
                    pass

            versions.append(version_info)

    return versions


def get_recent_logs(logs_dir: str, max_lines: int = 500) -> Optional[str]:
    """Read the most recent log file."""
    if not os.path.isdir(logs_dir):
        return None

    latest_log = os.path.join(logs_dir, "latest.log")
    if os.path.isfile(latest_log):
        try:
            with open(latest_log, "r", errors="replace") as f:
                lines = f.readlines()
            return "".join(lines[-max_lines:])
        except Exception:
            pass

    return None


def full_launcher_scan() -> Dict:
    """Perform a full scan of all detected launchers."""
    launchers = detect_launchers()

    result = {
        "launchers_found": len(launchers),
        "launchers": [],
        "total_mods_dirs": 0,
        "total_mod_files": 0,
    }

    for launcher in launchers:
        launcher_data = {
            "name": launcher["name"],
            "path": launcher["path"],
            "instances": launcher["instances"],
            "mods": [],
            "versions": [],
            "has_logs": False,
        }

        for mods_dir in launcher["mods_dirs"]:
            mods = get_mod_files(mods_dir)
            launcher_data["mods"].extend(mods)
            result["total_mods_dirs"] += 1
            result["total_mod_files"] += len(mods)

        for ver_dir in launcher["versions_dirs"]:
            versions = get_versions(ver_dir)
            launcher_data["versions"].extend(versions)

        launcher_data["has_logs"] = len(launcher["logs_dirs"]) > 0
        result["launchers"].append(launcher_data)

    return result
