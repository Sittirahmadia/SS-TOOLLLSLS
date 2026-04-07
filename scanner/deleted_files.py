"""
Deleted Files Scanner - Unified
Merged from deleted_files.py + deleted_files_advanced.py
- Recycle Bin scanning (Windows)
- Prefetch file analysis
- Temp directory scanning
- File signature detection & recovery scoring
- System-wide deleted file detection
"""

import os
import sys
import struct
import platform
import glob
import datetime
from typing import List, Dict, Optional
from pathlib import Path

try:
    from .cheat_detector import detect_cheats
except ImportError:
    detect_cheats = None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FILE SIGNATURES FOR CARVING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FILE_SIGNATURES = {
    'pdf': b'%PDF',
    'jpeg': b'\xff\xd8\xff',
    'png': b'\x89PNG\r\n\x1a\n',
    'gif': b'GIF8',
    'zip': b'PK\x03\x04',
    'exe': b'MZ',
    'dll': b'MZ',
    'bmp': b'BM',
    'avi': b'RIFF',
    'mp3': b'\xff\xfb',
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HELPER FUNCTIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_appdata() -> str:
    if platform.system() == "Windows":
        return os.environ.get("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))
    return os.path.expanduser("~")


def get_local_appdata() -> str:
    if platform.system() == "Windows":
        return os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
    return os.path.expanduser("~/.local/share")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WINDOWS: RECYCLE BIN SCANNING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_recycle_info(info_path: str) -> Optional[Dict]:
    try:
        with open(info_path, "rb") as f:
            data = f.read()
        if len(data) < 28:
            return None
        version = struct.unpack("<Q", data[0:8])[0]
        file_size = struct.unpack("<Q", data[8:16])[0]
        filetime = struct.unpack("<Q", data[16:24])[0]
        try:
            timestamp = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)
            deletion_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            deletion_time = "Unknown"
        if version == 2:
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


def get_recycle_bin_items() -> List[Dict]:
    items = []
    if platform.system() != "Windows":
        return items
    try:
        for drive_letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WINDOWS: PREFETCH FILES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_prefetch_files() -> List[Dict]:
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
                    name_part = f.rsplit("-", 1)[0] if "-" in f else f.replace(".pf", "")
                    items.append({
                        "filename": f,
                        "program_name": name_part,
                        "path": fpath,
                        "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "size": stat.st_size,
                    })
                except Exception:
                    continue
    except PermissionError:
        items.append({"error": "Access denied to Prefetch directory (run as Administrator)"})
    except Exception:
        pass
    return items


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TEMP FILES SCANNING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_temp_files() -> List[Dict]:
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
                            "filename": f, "path": fpath, "extension": ext,
                            "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                            "size": stat.st_size,
                            "size_mb": round(stat.st_size / (1024 * 1024), 2),
                        })
                    except Exception:
                        continue
        except (PermissionError, Exception):
            continue
    return items


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ADVANCED: FILE SIGNATURE ANALYSIS & DIRECTORY SCANNING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DeletedFilesScanner:
    """Advanced deleted file detection with signature analysis."""

    def __init__(self):
        self.found_files = []

    def scan_directory(self, path: str, max_depth: int = 3) -> dict:
        result = {
            'total_files': 0, 'deleted_candidates': [],
            'recovery_possible': 0, 'risk_level': 'CLEAN', 'summary': {}
        }
        try:
            for root, dirs, files in os.walk(path):
                depth = root.count(os.sep) - path.count(os.sep)
                if depth > max_depth:
                    dirs[:] = []
                    continue
                result['total_files'] += len(files)
                for file in files[:100]:
                    full_path = os.path.join(root, file)
                    try:
                        file_result = self._analyze_file(full_path)
                        if file_result['suspicious']:
                            result['deleted_candidates'].append(file_result)
                            result['recovery_possible'] += 1
                    except Exception:
                        pass
            if result['deleted_candidates']:
                result['risk_level'] = 'HIGH - Deleted Files Found'
            result['summary'] = self._generate_summary(result['deleted_candidates'])
        except Exception as e:
            result['error'] = str(e)
        return result

    def _analyze_file(self, file_path: str) -> dict:
        result = {
            'file': os.path.basename(file_path), 'path': file_path,
            'suspicious': False, 'indicators': [], 'recovery_score': 0, 'type': 'unknown'
        }
        try:
            stat = os.stat(file_path)
            indicators = []

            # Hidden files (Windows)
            if os.name == 'nt':
                try:
                    import ctypes
                    attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
                    if attrs & 2:
                        indicators.append('hidden_file')
                        result['recovery_score'] += 15
                except Exception:
                    pass

            # Recently modified
            if abs(stat.st_mtime - stat.st_atime) < 3600:
                indicators.append('recent_modification')
                result['recovery_score'] += 20

            # Zero/small size
            if stat.st_size == 0:
                indicators.append('zero_size')
                result['recovery_score'] += 25
            elif stat.st_size < 512:
                indicators.append('very_small')
                result['recovery_score'] += 10

            # File signature check
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(512)
                for file_type, sig in FILE_SIGNATURES.items():
                    if header.startswith(sig):
                        result['type'] = file_type
                        result['recovery_score'] += 30
                        indicators.append(f'signature_match:{file_type}')
                        break
            except Exception:
                pass

            # Suspicious filename patterns
            filename_lower = os.path.basename(file_path).lower()
            sus_patterns = ['temp', 'tmp', 'cache', 'recycle', 'trash', 'thumbs.db', 'desktop.ini']
            if any(p in filename_lower for p in sus_patterns):
                indicators.append('suspicious_location')
                result['recovery_score'] += 15

            result['indicators'] = indicators
            result['suspicious'] = len(indicators) > 0
        except Exception:
            pass
        return result

    def _generate_summary(self, candidates: list) -> dict:
        summary = {'by_type': {}, 'by_indicator': {}, 'recovery_stats': {'excellent': 0, 'good': 0, 'fair': 0, 'poor': 0}}
        for c in candidates:
            ftype = c.get('type', 'unknown')
            summary['by_type'][ftype] = summary['by_type'].get(ftype, 0) + 1
            for ind in c.get('indicators', []):
                summary['by_indicator'][ind] = summary['by_indicator'].get(ind, 0) + 1
            score = c.get('recovery_score', 0)
            if score > 80: summary['recovery_stats']['excellent'] += 1
            elif score > 60: summary['recovery_stats']['good'] += 1
            elif score > 40: summary['recovery_stats']['fair'] += 1
            else: summary['recovery_stats']['poor'] += 1
        return summary

    def scan_system(self) -> dict:
        result = {'windows': None, 'users': None, 'temp': None, 'total_deleted': 0, 'risk_level': 'CLEAN'}
        try:
            if sys.platform == 'win32':
                temp_path = os.environ.get('TEMP', 'C:\\Windows\\Temp')
                result['temp'] = self.scan_directory(temp_path)
                result['total_deleted'] += result['temp'].get('recovery_possible', 0)
                users_path = os.environ.get('USERPROFILE', 'C:\\Users')
                if os.path.exists(users_path):
                    result['users'] = self.scan_directory(users_path, max_depth=2)
                    result['total_deleted'] += result['users'].get('recovery_possible', 0)
            else:
                result['temp'] = self.scan_directory('/tmp')
                result['total_deleted'] += result['temp'].get('recovery_possible', 0)
                home = os.path.expanduser('~')
                result['users'] = self.scan_directory(home, max_depth=2)
                result['total_deleted'] += result['users'].get('recovery_possible', 0)
            if result['total_deleted'] > 0:
                result['risk_level'] = 'MEDIUM - Deleted Files Detected'
        except Exception as e:
            result['error'] = str(e)
        return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FULL SCAN (combines all sources)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def scan_deleted_files() -> Dict:
    """Full deleted file scan - Recycle Bin + Prefetch + Temp + Advanced."""
    recycle_bin = get_recycle_bin_items()
    prefetch = get_prefetch_files()
    temp = get_temp_files()

    flagged_items = []

    if detect_cheats:
        for item in recycle_bin:
            if "filename" in item:
                detections = detect_cheats(item.get("filename", ""), item.get("filename", ""), item.get("original_path", ""))
                if detections:
                    item["detections"] = [{"name": d.name, "severity": d.severity, "category": d.category} for d in detections]
                    item["source"] = "Recycle Bin"
                    flagged_items.append(item)

        for item in prefetch:
            if "program_name" in item:
                detections = detect_cheats(item.get("program_name", ""), item.get("filename", ""), item.get("path", ""))
                if detections:
                    item["detections"] = [{"name": d.name, "severity": d.severity, "category": d.category} for d in detections]
                    item["source"] = "Prefetch"
                    flagged_items.append(item)

        for item in temp:
            if "filename" in item:
                detections = detect_cheats(item.get("filename", ""), item.get("filename", ""), item.get("path", ""))
                if detections:
                    item["detections"] = [{"name": d.name, "severity": d.severity, "category": d.category} for d in detections]
                    item["source"] = "Temp"
                    flagged_items.append(item)

    return {
        "recycle_bin": {"count": len(recycle_bin), "items": recycle_bin[:100]},
        "prefetch": {"count": len(prefetch), "items": prefetch[:200]},
        "temp_files": {"count": len(temp), "items": temp[:200]},
        "flagged_deleted_items": flagged_items,
        "total_scanned": len(recycle_bin) + len(prefetch) + len(temp),
    }


if __name__ == '__main__':
    import json
    scanner = DeletedFilesScanner()
    result = scanner.scan_system()
    print(json.dumps(result, indent=2, default=str))
