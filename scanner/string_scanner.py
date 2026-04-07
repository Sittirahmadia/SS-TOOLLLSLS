"""
String Scanner
Deep scans files for cheat-related strings, DLLs, EXEs, and macro signatures.
Handles binary and text files, including obfuscated strings.
"""

import os
import re
from typing import List, Dict, Set
from .cheat_detector import detect_cheats, CHEAT_SIGNATURES


# Additional string patterns for deep scanning
INJECTOR_PATTERNS = [
    # DLL injection APIs (Windows)
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtCreateThreadEx", "RtlCreateUserThread",
    "VirtualAllocEx", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "NtWriteVirtualMemory", "NtReadVirtualMemory",
    "SetWindowsHookEx", "QueueUserAPC",

    # Process manipulation
    "OpenProcess", "NtOpenProcess",
    "NtSuspendProcess", "NtResumeProcess",
    "EnumProcessModules", "CreateToolhelp32Snapshot",
]

MACRO_PATTERNS = [
    # Known macro tools
    "198macro", "198_macro", "198 macro",
    "zenithmacro", "zenith_macro", "zenith macro",
    "opmacro", "op_macro",
    "crystalmacro", "crystal_macro",
    "cpvpmacro",
    "anchorbot",

    # Generic macro indicators
    "hotkey_toggle", "macro_enabled",
    "click_delay", "click_speed",
    "auto_click", "auto_place",
    "crystal_speed", "crystal_delay",
    "swap_delay", "switch_delay",
    "anchor_delay", "bed_delay",
]

CHEAT_STRING_PATTERNS = [
    # Module system indicators
    "ModuleCategory", "ModuleManager", "HackManager",
    "CheatManager", "FeatureManager",
    "MODULE_COMBAT", "MODULE_MOVEMENT", "MODULE_RENDER",
    "MODULE_PLAYER", "MODULE_WORLD", "MODULE_MISC",
    "MODULE_CLIENT", "MODULE_EXPLOIT",

    # Hack indicators
    "onEnable", "onDisable", "isEnabled",
    "getCategory", "getDescription",
    "setEnabled", "toggleModule",
    "hackList", "enabledHacks",

    # Networking cheats
    "PacketListener", "PacketHandler",
    "sendPacketDirect", "cancelPacket",
    "spoofPacket", "modifyPacket",

    # Anti-anticheat
    "bypassCheck", "anticheatBypass",
    "disableAC", "acDisabler",
    "watchdogBypass", "sentinelBypass",
    "vulcanBypass", "grimBypass",
    "nocomBypass",
]


def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """Extract printable ASCII and UTF-16 strings from binary data."""
    strings = []

    # ASCII strings
    ascii_pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    for match in ascii_pattern.finditer(data):
        try:
            strings.append(match.group().decode('ascii'))
        except Exception:
            pass

    # UTF-16 LE strings (common in Windows binaries)
    utf16_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % min_length)
    for match in utf16_pattern.finditer(data):
        try:
            strings.append(match.group().decode('utf-16-le'))
        except Exception:
            pass

    return strings


def scan_file_strings(file_path: str) -> Dict:
    """Scan a single file for suspicious strings."""
    result = {
        "path": file_path,
        "filename": os.path.basename(file_path),
        "size_mb": 0,
        "injector_matches": [],
        "macro_matches": [],
        "cheat_matches": [],
        "cheat_detections": [],
        "error": None,
    }

    try:
        stat = os.stat(file_path)
        result["size_mb"] = round(stat.st_size / (1024 * 1024), 2)

        # Limit scan to 100MB files
        if stat.st_size > 100 * 1024 * 1024:
            result["error"] = "File too large (>100MB)"
            return result

        with open(file_path, "rb") as f:
            data = f.read()

        strings = extract_strings(data)
        all_text = " ".join(strings).lower()

        # Check injector patterns
        for pattern in INJECTOR_PATTERNS:
            if pattern.lower() in all_text:
                result["injector_matches"].append(pattern)

        # Check macro patterns
        for pattern in MACRO_PATTERNS:
            if pattern.lower() in all_text:
                result["macro_matches"].append(pattern)

        # Check cheat string patterns
        for pattern in CHEAT_STRING_PATTERNS:
            if pattern.lower() in all_text:
                result["cheat_matches"].append(pattern)

        # Run full cheat detection
        detections = detect_cheats(all_text, os.path.basename(file_path), file_path)
        result["cheat_detections"] = [
            {
                "name": d.signature_name,
                "category": d.category,
                "severity": d.severity,
                "confidence": d.confidence,
                "matched": d.matched_patterns,
            }
            for d in detections
        ]

    except PermissionError:
        result["error"] = "Permission denied"
    except Exception as e:
        result["error"] = str(e)

    return result


def scan_directory_for_strings(directory: str,
                                extensions: Set[str] = None,
                                max_depth: int = 3) -> List[Dict]:
    """Scan a directory tree for suspicious files."""
    if extensions is None:
        extensions = {".exe", ".dll", ".jar", ".zip", ".bat", ".cmd", ".ps1", ".sys"}

    results = []
    scanned = 0

    for root, dirs, files in os.walk(directory):
        # Check depth
        depth = root.replace(directory, "").count(os.sep)
        if depth > max_depth:
            continue

        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in extensions:
                fpath = os.path.join(root, f)
                result = scan_file_strings(fpath)

                # Only include if something was found
                if (result["injector_matches"] or
                    result["macro_matches"] or
                    result["cheat_matches"] or
                    result["cheat_detections"]):
                    results.append(result)

                scanned += 1

    return results


def scan_task_manager_binaries() -> List[Dict]:
    """
    Scan for suspicious executables that might be hidden from task manager.
    Checks common locations where macros/injectors hide.
    """
    results = []

    suspicious_dirs = []
    if os.name == "nt":
        home = os.path.expanduser("~")
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")

        suspicious_dirs = [
            os.path.join(appdata, "Local"),
            os.path.join(localappdata, "Temp"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Documents"),
            os.path.join(appdata),
            os.path.join(localappdata),
        ]
    else:
        home = os.path.expanduser("~")
        suspicious_dirs = [
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            "/tmp",
        ]

    for d in suspicious_dirs:
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    fpath = os.path.join(d, f)
                    if not os.path.isfile(fpath):
                        continue

                    ext = os.path.splitext(f)[1].lower()
                    name_lower = f.lower()

                    # Check for known macro/injector filenames
                    suspicious = False
                    reason = ""

                    known_names = [
                        "198macro", "zenithmacro", "crystalmacro",
                        "injector", "autoclicker", "processhacker",
                        "cheatengine", "extremeinjector", "xenos",
                    ]

                    for kn in known_names:
                        if kn in name_lower:
                            suspicious = True
                            reason = f"Known tool: {kn}"
                            break

                    if ext in (".exe", ".dll") and not suspicious:
                        # Check for hidden executables with random names
                        if len(f.replace(ext, "")) > 20 and all(c.isalnum() for c in f.replace(ext, "")):
                            suspicious = True
                            reason = "Randomly named executable"

                    if suspicious:
                        results.append({
                            "path": fpath,
                            "filename": f,
                            "reason": reason,
                            "size_mb": round(os.path.getsize(fpath) / (1024 * 1024), 2),
                        })
            except Exception:
                continue

    return results
