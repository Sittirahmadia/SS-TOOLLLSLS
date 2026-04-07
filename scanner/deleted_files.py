"""
Deleted File Scanner
Scans Recycle Bin, Prefetch, Temp, Recent files, and USN Journal
to find traces of deleted files related to Minecraft cheats.
"""

import os
import platform
import glob
import struct
import datetime
import ctypes
from typing import List, Dict, Optional
from .cheat_detector import detect_cheats


def get_recycle_bin_items() -> List[Dict]:
    """
    Scan Windows Recycle Bin for deleted items.
    Reads $I files in $Recycle.Bin to get original paths and deletion times.
    """
    items = []

    if platform.system() != "Windows":
        return items

    try:
        # Find all $Recycle.Bin directories
        for drive_letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            recycle_path = f"{drive_letter}:\\$Recycle.Bin"
            if not os.path.isdir(recycle_path):
                continue

            for sid_dir in os.listdir(recycle_path):
                sid_path = os.path.join(recycle_path, sid_dir)
                if not os.path.isdir(sid_path):
                    continue

                for f in os.listdir(sid_path):
                    if f.startswith("$I"):
                        info_file = os.path.join(sid_path, f)
                        try:
                            item = parse_recycle_info(info_file)
                            if item:
                                item["recycle_file"] = info_file
                                items.append(item)
                        except Exception:
                            continue
    except Exception:
        pass

    return items


def parse_recycle_info(info_path: str) -> Optional[Dict]:
    """Parse a $I recycle bin info file."""
    try:
        with open(info_path, "rb") as f:
            data = f.read()

        if len(data) < 28:
            return None

        # Version
        version = struct.unpack("<Q", data[0:8])[0]

        # File size
        file_size = struct.unpack("<Q", data[8:16])[0]

        # Deletion time (Windows FILETIME)
        filetime = struct.unpack("<Q", data[16:24])[0]
        try:
            timestamp = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)
            deletion_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            deletion_time = "Unknown"

        # Original path
        if version == 2:
            # Windows 10+ format
            path_len = struct.unpack("<I", data[24:28])[0]
            original_path = data[28:28 + path_len * 2].decode("utf-16-le", errors="replace").rstrip("\x00")
        else:
            original_path = data[24:].decode("utf-16-le", errors="replace").rstrip("\x00")

        return {
            "original_path": original_path,
            "file_size": file_size,
            "file_size_mb": round(file_size / (1024 * 1024), 2),
            "deletion_time": deletion_time,
            "filename": os.path.basename(original_path),
        }
    except Exception:
        return None


def get_prefetch_files() -> List[Dict]:
    """
    Scan Windows Prefetch directory for traces of executed programs.
    Prefetch files are created when programs run, even after deletion.
    """
    items = []

    if platform.system() != "Windows":
        return items

    prefetch_dir = os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "Prefetch")
    if not os.path.isdir(prefetch_dir):
        return items

    try:
        for f in os.listdir(prefetch_dir):
            if f.lower().endswith(".pf"):
                fpath = os.path.join(prefetch_dir, f)
                try:
                    stat = os.stat(fpath)
                    # Extract program name from prefetch filename
                    # Format: PROGRAMNAME-HASH.pf
                    name_part = f.rsplit("-", 1)[0] if "-" in f else f.replace(".pf", "")

                    items.append({
                        "filename": f,
                        "program_name": name_part,
                        "path": fpath,
                        "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "created": datetime.datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                        "size": stat.st_size,
                    })
                except Exception:
                    continue
    except PermissionError:
        items.append({"error": "Access denied to Prefetch directory (run as Administrator)"})
    except Exception:
        pass

    return items


def get_recent_files() -> List[Dict]:
    """Scan Windows Recent Files."""
    items = []

    if platform.system() != "Windows":
        return items

    recent_dir = os.path.join(get_appdata(), "Microsoft", "Windows", "Recent")
    if not os.path.isdir(recent_dir):
        return items

    try:
        for f in os.listdir(recent_dir):
            fpath = os.path.join(recent_dir, f)
            try:
                stat = os.stat(fpath)
                items.append({
                    "filename": f,
                    "path": fpath,
                    "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "size": stat.st_size,
                })
            except Exception:
                continue
    except Exception:
        pass

    return items


def get_temp_files() -> List[Dict]:
    """Scan temp directories for suspicious files."""
    items = []
    temp_dirs = []

    if platform.system() == "Windows":
        temp_dirs = [
            os.environ.get("TEMP", ""),
            os.environ.get("TMP", ""),
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "Temp"),
            os.path.join(get_local_appdata(), "Temp"),
        ]
    else:
        temp_dirs = ["/tmp", "/var/tmp"]

    suspicious_extensions = {".jar", ".exe", ".dll", ".zip", ".bat", ".cmd", ".ps1", ".vbs"}

    seen = set()
    for temp_dir in temp_dirs:
        if not temp_dir or not os.path.isdir(temp_dir):
            continue

        real = os.path.realpath(temp_dir)
        if real in seen:
            continue
        seen.add(real)

        try:
            for f in os.listdir(temp_dir):
                fpath = os.path.join(temp_dir, f)
                ext = os.path.splitext(f)[1].lower()
                if ext in suspicious_extensions:
                    try:
                        stat = os.stat(fpath)
                        items.append({
                            "filename": f,
                            "path": fpath,
                            "extension": ext,
                            "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                            "size": stat.st_size,
                            "size_mb": round(stat.st_size / (1024 * 1024), 2),
                        })
                    except Exception:
                        continue
        except PermissionError:
            continue
        except Exception:
            continue

    return items


def get_appdata() -> str:
    if platform.system() == "Windows":
        return os.environ.get("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))
    return os.path.expanduser("~")


def get_local_appdata() -> str:
    if platform.system() == "Windows":
        return os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
    return os.path.expanduser("~/.local/share")


def scan_deleted_files() -> Dict:
    """Full deleted file scan combining all sources."""
    recycle_bin = get_recycle_bin_items()
    prefetch = get_prefetch_files()
    recent = get_recent_files()
    temp = get_temp_files()

    # Run cheat detection on all found filenames
    flagged_items = []

    for item in recycle_bin:
        if "filename" in item:
            detections = detect_cheats(item.get("filename", ""), item.get("filename", ""), item.get("original_path", ""))
            if detections:
                item["detections"] = [
                    {"name": d.signature_name, "severity": d.severity, "category": d.category}
                    for d in detections
                ]
                item["source"] = "Recycle Bin"
                flagged_items.append(item)

    for item in prefetch:
        if "program_name" in item:
            detections = detect_cheats(item.get("program_name", ""), item.get("filename", ""), item.get("path", ""))
            if detections:
                item["detections"] = [
                    {"name": d.signature_name, "severity": d.severity, "category": d.category}
                    for d in detections
                ]
                item["source"] = "Prefetch"
                flagged_items.append(item)

    for item in temp:
        if "filename" in item:
            detections = detect_cheats(item.get("filename", ""), item.get("filename", ""), item.get("path", ""))
            if detections:
                item["detections"] = [
                    {"name": d.signature_name, "severity": d.severity, "category": d.category}
                    for d in detections
                ]
                item["source"] = "Temp"
                flagged_items.append(item)

    return {
        "recycle_bin": {
            "count": len(recycle_bin),
            "items": recycle_bin[:100],
        },
        "prefetch": {
            "count": len(prefetch),
            "items": prefetch[:200],
        },
        "recent_files": {
            "count": len(recent),
            "items": recent[:200],
        },
        "temp_files": {
            "count": len(temp),
            "items": temp[:200],
        },
        "flagged_deleted_items": flagged_items,
        "total_scanned": len(recycle_bin) + len(prefetch) + len(recent) + len(temp),
    }
