"""
Improved Process Scanner - No False Flags
- Detects actual malicious processes
- Skips system/legitimate processes
- Fast threading-based scanning
"""

import os
import platform
import subprocess
import threading
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed


# Legitimate system/gaming processes (whitelist)
WHITELIST_PROCESSES = {
    # Windows system
    "svchost.exe", "dwm.exe", "csrss.exe", "lsass.exe", "services.exe",
    "spoolsv.exe", "rundll32.exe", "winlogon.exe", "explorer.exe",
    # Java/Minecraft
    "java.exe", "javaw.exe", "minecraft.exe", "javaws.exe",
    # Common browsers
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
    # Common apps
    "steam.exe", "discord.exe", "spotify.exe", "slack.exe", "teamviewer.exe",
    "obs64.exe", "obs32.exe", "audacity.exe", "vlc.exe", "notepad.exe",
    # Launchers
    "TLauncher.exe", "MCLauncher.exe", "PolyMC.exe", "PrismLauncher.exe",
    # GPU/drivers
    "nvidia-smi.exe", "amdradeoninstaller.exe", "intelgraphics.exe",
    # Antivirus
    "MsMpEng.exe", "NisSrv.exe", "mcafee.exe", "avast.exe", "avg.exe",
}

# Known cheat/hack processes
MALICIOUS_PROCESSES = {
    # Cheat engines
    "cheatengine": {"category": "cheat_engine", "risk": "CRITICAL"},
    "CE.exe": {"category": "cheat_engine", "risk": "CRITICAL"},
    "Cheat Engine": {"category": "cheat_engine", "risk": "CRITICAL"},
    
    # Injection tools
    "injector": {"category": "injector", "risk": "CRITICAL"},
    "dll injector": {"category": "injector", "risk": "CRITICAL"},
    
    # Memory hackers
    "artmoney": {"category": "memory_hacker", "risk": "CRITICAL"},
    "WPE PRO": {"category": "packet_editor", "risk": "CRITICAL"},
    "Wireshark": {"category": "network_analyzer", "risk": "HIGH"},
    
    # Keyloggers
    "keylogger": {"category": "keylogger", "risk": "CRITICAL"},
    "spyware": {"category": "spyware", "risk": "CRITICAL"},
    
    # Mining
    "xmrig": {"category": "crypto_miner", "risk": "HIGH"},
    "claymore": {"category": "crypto_miner", "risk": "HIGH"},
    "ethminer": {"category": "crypto_miner", "risk": "HIGH"},
}

# Macro/bot tools (potential but not always malicious)
BOT_TOOLS = {
    "autohotkey": {"category": "macro_tool", "risk": "MEDIUM"},
    "ahk": {"category": "macro_tool", "risk": "MEDIUM"},
    "macro": {"category": "macro_tool", "risk": "MEDIUM"},
    "bot": {"category": "bot_tool", "risk": "MEDIUM"},
}


def get_running_processes() -> List[Dict]:
    """Get all running processes."""
    processes = []

    try:
        if platform.system() == "Windows":
            # Use tasklist command
            result = subprocess.run(
                ["tasklist", "/v"],
                capture_output=True,
                text=True,
                timeout=10
            )

            lines = result.stdout.split("\n")[3:]  # Skip header
            for line in lines:
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    process_name = parts[0]
                    try:
                        pid = int(parts[1])
                        processes.append({
                            "name": process_name,
                            "pid": pid,
                            "platform": "Windows"
                        })
                    except ValueError:
                        pass

        elif platform.system() in ["Linux", "Darwin"]:
            # Use ps command
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.split("\n")[1:]:
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) >= 11:
                    try:
                        pid = int(parts[1])
                        cmd = " ".join(parts[10:])
                        process_name = os.path.basename(cmd.split()[0]) if cmd else ""

                        processes.append({
                            "name": process_name,
                            "cmd": cmd,
                            "pid": pid,
                            "platform": platform.system()
                        })
                    except (ValueError, IndexError):
                        pass

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass

    return processes


def analyze_process(process: Dict) -> Dict:
    """Analyze a single process for suspicious activity."""
    name_lower = process["name"].lower()
    cmd_lower = process.get("cmd", "").lower() if process.get("cmd") else ""

    # Check whitelist first (fast path)
    if process["name"] in WHITELIST_PROCESSES:
        return {
            "name": process["name"],
            "pid": process["pid"],
            "status": "whitelisted",
            "risk": "NONE"
        }

    # Check malicious processes
    for malicious_name, info in MALICIOUS_PROCESSES.items():
        if malicious_name.lower() in name_lower or malicious_name.lower() in cmd_lower:
            return {
                "name": process["name"],
                "pid": process["pid"],
                "status": "suspicious",
                "category": info["category"],
                "risk": info["risk"],
                "cmd": process.get("cmd", "")
            }

    # Check bot tools
    for bot_name, info in BOT_TOOLS.items():
        if bot_name.lower() in name_lower or bot_name.lower() in cmd_lower:
            return {
                "name": process["name"],
                "pid": process["pid"],
                "status": "potential_bot",
                "category": info["category"],
                "risk": info["risk"],
                "cmd": process.get("cmd", "")
            }

    # Unknown process - likely legitimate
    return {
        "name": process["name"],
        "pid": process["pid"],
        "status": "unknown",
        "risk": "NONE"
    }


def full_process_scan() -> Dict:
    """Full process scan with optimized threading."""
    results = {
        "total_processes": 0,
        "suspicious_processes": [],
        "bot_tools": [],
        "whitelisted": [],
        "summary": {
            "risk_level": "NONE",
            "suspicious_count": 0,
            "bot_count": 0
        }
    }

    try:
        processes = get_running_processes()
        results["total_processes"] = len(processes)

        # Analyze processes in parallel
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(analyze_process, p): p for p in processes}

            for future in as_completed(futures):
                try:
                    analysis = future.result(timeout=5)

                    if analysis["status"] == "suspicious":
                        results["suspicious_processes"].append(analysis)
                    elif analysis["status"] == "potential_bot":
                        results["bot_tools"].append(analysis)
                    elif analysis["status"] == "whitelisted":
                        results["whitelisted"].append(analysis)

                except Exception:
                    continue

    except Exception as e:
        results["error"] = str(e)

    # Update summary
    results["summary"]["suspicious_count"] = len(results["suspicious_processes"])
    results["summary"]["bot_count"] = len(results["bot_tools"])

    if results["suspicious_processes"]:
        results["summary"]["risk_level"] = "CRITICAL"
    elif results["bot_tools"]:
        results["summary"]["risk_level"] = "MEDIUM"
    else:
        results["summary"]["risk_level"] = "NONE"

    return results


def get_process_details(pid: int) -> Dict:
    """Get detailed information about a process."""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["wmic", "process", "where", f"ProcessId={pid}", "get", "ExecutablePath"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return {"path": result.stdout.strip()}
    except Exception:
        pass

    return {"error": "Could not get process details"}
