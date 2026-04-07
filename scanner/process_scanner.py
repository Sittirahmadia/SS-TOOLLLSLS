"""
Process Scanner
Scans running processes via task manager equivalent.
Detects injectors, DLL injection tools, macro tools,
Process Hacker, and suspicious Minecraft-related processes.
"""

import os
import platform
import subprocess
import datetime
from typing import List, Dict

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# Suspicious process names (lowercase)
SUSPICIOUS_PROCESSES = {
    # Injection tools
    "processhacker.exe": {"category": "Injection Tool", "severity": "critical", "desc": "Process Hacker - can inject DLLs into processes"},
    "processhacker2.exe": {"category": "Injection Tool", "severity": "critical", "desc": "Process Hacker 2"},
    "systeminformer.exe": {"category": "Injection Tool", "severity": "critical", "desc": "System Informer (Process Hacker rebrand)"},
    "injector.exe": {"category": "Injection Tool", "severity": "critical", "desc": "Generic DLL injector"},
    "extremeinjector.exe": {"category": "Injection Tool", "severity": "critical", "desc": "Extreme Injector"},
    "xenos.exe": {"category": "Injection Tool", "severity": "critical", "desc": "Xenos injector"},
    "xenos64.exe": {"category": "Injection Tool", "severity": "critical", "desc": "Xenos injector (64-bit)"},

    # Macro tools
    "198macro.exe": {"category": "Macro Tool", "severity": "critical", "desc": "198Macro - Crystal PvP macro"},
    "zenithmacro.exe": {"category": "Macro Tool", "severity": "critical", "desc": "ZenithMacro - PvP macro"},
    "crystalmacro.exe": {"category": "Macro Tool", "severity": "critical", "desc": "Crystal Macro"},
    "autoclicker.exe": {"category": "Macro Tool", "severity": "high", "desc": "Auto clicker detected"},
    "fastclicker.exe": {"category": "Macro Tool", "severity": "high", "desc": "Fast clicker detected"},
    "clickspeed.exe": {"category": "Macro Tool", "severity": "high", "desc": "Click speed tool"},
    "opmacro.exe": {"category": "Macro Tool", "severity": "critical", "desc": "OP Macro"},
    "macrorecorder.exe": {"category": "Macro Tool", "severity": "medium", "desc": "Macro recorder"},

    # Cheat clients (standalone)
    "wurst.exe": {"category": "Cheat Client", "severity": "critical", "desc": "Wurst Client"},
    "impact.exe": {"category": "Cheat Client", "severity": "critical", "desc": "Impact Client"},
    "aristois.exe": {"category": "Cheat Client", "severity": "critical", "desc": "Aristois Client"},
    "liquidbounce.exe": {"category": "Cheat Client", "severity": "critical", "desc": "LiquidBounce"},
    "sigma.exe": {"category": "Cheat Client", "severity": "critical", "desc": "Sigma Client"},

    # Memory editing
    "cheatengine.exe": {"category": "Memory Editor", "severity": "critical", "desc": "Cheat Engine"},
    "cheatengine-x86_64.exe": {"category": "Memory Editor", "severity": "critical", "desc": "Cheat Engine (64-bit)"},
    "artmoney.exe": {"category": "Memory Editor", "severity": "critical", "desc": "ArtMoney memory editor"},
    "gameguardian.exe": {"category": "Memory Editor", "severity": "critical", "desc": "Game Guardian"},

    # Debuggers that can be used for injection
    "x64dbg.exe": {"category": "Debugger", "severity": "high", "desc": "x64dbg debugger"},
    "x32dbg.exe": {"category": "Debugger", "severity": "high", "desc": "x32dbg debugger"},
    "ollydbg.exe": {"category": "Debugger", "severity": "high", "desc": "OllyDbg debugger"},
    "ida.exe": {"category": "Debugger", "severity": "medium", "desc": "IDA Pro disassembler"},
    "ida64.exe": {"category": "Debugger", "severity": "medium", "desc": "IDA Pro 64-bit"},

    # Screen sharing avoidance
    "hidetoolz.exe": {"category": "Evasion", "severity": "critical", "desc": "HideToolz - hides processes"},
    "processhider.exe": {"category": "Evasion", "severity": "critical", "desc": "Process Hider"},
}

# Suspicious Java process arguments
SUSPICIOUS_JAVA_ARGS = [
    "meteor", "wurst", "impact", "aristois", "future",
    "phobos", "konas", "gamesense", "earthhack", "salhack",
    "forgehax", "bleachhack", "rusherhack", "thunderhack",
    "coffeeclient", "liquidbounce", "inertia", "lambda",
    "kamiblue", "cornos", "abyss", "azura", "matix", "sigma",
]


def scan_processes() -> Dict:
    """Scan all running processes for suspicious activity."""
    result = {
        "total_processes": 0,
        "suspicious_processes": [],
        "java_processes": [],
        "minecraft_processes": [],
        "hidden_process_check": False,
        "error": None,
    }

    if not HAS_PSUTIL:
        # Fallback: use tasklist on Windows
        if platform.system() == "Windows":
            return scan_processes_tasklist()
        result["error"] = "psutil not installed - limited process scanning"
        return result

    try:
        processes = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'username', 'memory_info', 'cpu_percent']))
        result["total_processes"] = len(processes)

        for proc in processes:
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                exe = info.get("exe") or ""
                cmdline = info.get("cmdline") or []
                cmdline_str = " ".join(cmdline).lower()

                # Check against suspicious processes
                if name in SUSPICIOUS_PROCESSES:
                    sus_info = SUSPICIOUS_PROCESSES[name]
                    result["suspicious_processes"].append({
                        "pid": info["pid"],
                        "name": info["name"],
                        "exe": exe,
                        "category": sus_info["category"],
                        "severity": sus_info["severity"],
                        "description": sus_info["desc"],
                        "start_time": datetime.datetime.fromtimestamp(info.get("create_time", 0)).strftime("%Y-%m-%d %H:%M:%S") if info.get("create_time") else "Unknown",
                        "memory_mb": round((info.get("memory_info") and info["memory_info"].rss or 0) / (1024 * 1024), 1),
                    })

                # Check Java processes (Minecraft runs on Java)
                if "java" in name or "javaw" in name:
                    java_info = {
                        "pid": info["pid"],
                        "name": info["name"],
                        "exe": exe,
                        "cmdline": " ".join(cmdline[:10]),  # First 10 args
                        "start_time": datetime.datetime.fromtimestamp(info.get("create_time", 0)).strftime("%Y-%m-%d %H:%M:%S") if info.get("create_time") else "Unknown",
                        "memory_mb": round((info.get("memory_info") and info["memory_info"].rss or 0) / (1024 * 1024), 1),
                        "suspicious_args": [],
                    }

                    # Check for suspicious Java arguments
                    for suspicious in SUSPICIOUS_JAVA_ARGS:
                        if suspicious in cmdline_str:
                            java_info["suspicious_args"].append(suspicious)

                    # Check if it's Minecraft
                    if "minecraft" in cmdline_str or "net.minecraft" in cmdline_str:
                        java_info["is_minecraft"] = True
                        result["minecraft_processes"].append(java_info)
                    else:
                        result["java_processes"].append(java_info)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    except Exception as e:
        result["error"] = str(e)

    return result


def scan_processes_tasklist() -> Dict:
    """Fallback: scan processes using Windows tasklist command."""
    result = {
        "total_processes": 0,
        "suspicious_processes": [],
        "java_processes": [],
        "minecraft_processes": [],
        "hidden_process_check": False,
        "error": None,
    }

    try:
        output = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/V"],
            text=True, timeout=30, stderr=subprocess.DEVNULL
        )

        lines = output.strip().split("\n")
        if len(lines) < 2:
            return result

        result["total_processes"] = len(lines) - 1

        for line in lines[1:]:
            parts = line.strip().strip('"').split('","')
            if len(parts) < 2:
                continue

            name = parts[0].strip('"').lower()
            pid = parts[1].strip('"') if len(parts) > 1 else "?"
            mem = parts[4].strip('"') if len(parts) > 4 else "?"

            if name in SUSPICIOUS_PROCESSES:
                sus_info = SUSPICIOUS_PROCESSES[name]
                result["suspicious_processes"].append({
                    "pid": pid,
                    "name": parts[0].strip('"'),
                    "category": sus_info["category"],
                    "severity": sus_info["severity"],
                    "description": sus_info["desc"],
                    "memory": mem,
                })

            if "java" in name:
                result["java_processes"].append({
                    "pid": pid,
                    "name": parts[0].strip('"'),
                    "memory": mem,
                })

    except Exception as e:
        result["error"] = f"tasklist fallback error: {str(e)}"

    return result


def check_hidden_processes() -> Dict:
    """
    Check for hidden processes by comparing different process listing methods.
    If a process is visible in one method but not another, it may be hidden.
    """
    result = {
        "possible_hidden": [],
        "check_performed": False,
        "error": None,
    }

    if platform.system() != "Windows":
        result["error"] = "Hidden process check only available on Windows"
        return result

    if not HAS_PSUTIL:
        result["error"] = "psutil required for hidden process check"
        return result

    try:
        # Method 1: psutil
        psutil_pids = set()
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                psutil_pids.add(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Method 2: tasklist
        tasklist_pids = set()
        try:
            output = subprocess.check_output(
                ["tasklist", "/FO", "CSV"],
                text=True, timeout=15, stderr=subprocess.DEVNULL
            )
            for line in output.strip().split("\n")[1:]:
                parts = line.strip().split('","')
                if len(parts) > 1:
                    try:
                        tasklist_pids.add(int(parts[1].strip('"')))
                    except ValueError:
                        continue
        except Exception:
            pass

        # Method 3: WMIC
        wmic_pids = set()
        try:
            output = subprocess.check_output(
                ["wmic", "process", "get", "processid"],
                text=True, timeout=15, stderr=subprocess.DEVNULL
            )
            for line in output.strip().split("\n"):
                line = line.strip()
                if line.isdigit():
                    wmic_pids.add(int(line))
        except Exception:
            pass

        result["check_performed"] = True

        # Find PIDs that exist in one method but not others
        all_pids = psutil_pids | tasklist_pids | wmic_pids
        for pid in all_pids:
            in_psutil = pid in psutil_pids
            in_tasklist = pid in tasklist_pids
            in_wmic = pid in wmic_pids

            # If not consistently visible, may be hidden
            if not (in_psutil and in_tasklist) and pid > 4:
                result["possible_hidden"].append({
                    "pid": pid,
                    "in_psutil": in_psutil,
                    "in_tasklist": in_tasklist,
                    "in_wmic": in_wmic,
                })

    except Exception as e:
        result["error"] = str(e)

    return result


def get_loaded_dlls(pid: int = None) -> List[Dict]:
    """Get loaded DLLs for a specific process or all Java processes."""
    dlls = []

    if not HAS_PSUTIL:
        return dlls

    try:
        if pid:
            processes = [psutil.Process(pid)]
        else:
            processes = [p for p in psutil.process_iter(['pid', 'name'])
                        if 'java' in (p.info.get('name') or '').lower()]

        for proc in processes:
            try:
                for dll in proc.memory_maps():
                    dll_name = os.path.basename(dll.path).lower()
                    # Check for suspicious DLLs
                    suspicious = False
                    reason = ""

                    suspicious_dll_patterns = [
                        "inject", "hook", "hack", "cheat", "exploit",
                        "aimbot", "esp", "wallhack", "bypass",
                    ]

                    for pattern in suspicious_dll_patterns:
                        if pattern in dll_name:
                            suspicious = True
                            reason = f"Contains '{pattern}' in name"
                            break

                    if suspicious:
                        dlls.append({
                            "pid": proc.pid,
                            "process_name": proc.name(),
                            "dll_path": dll.path,
                            "dll_name": dll_name,
                            "suspicious": True,
                            "reason": reason,
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    except Exception:
        pass

    return dlls


def full_process_scan() -> Dict:
    """Complete process scan including hidden process detection."""
    processes = scan_processes()
    hidden = check_hidden_processes()
    dlls = get_loaded_dlls()

    return {
        "processes": processes,
        "hidden_check": hidden,
        "suspicious_dlls": dlls,
        "summary": {
            "total_processes": processes["total_processes"],
            "suspicious_count": len(processes["suspicious_processes"]),
            "java_count": len(processes["java_processes"]),
            "minecraft_count": len(processes["minecraft_processes"]),
            "hidden_count": len(hidden.get("possible_hidden", [])),
            "suspicious_dll_count": len(dlls),
        }
    }
