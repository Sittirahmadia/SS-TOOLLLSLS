"""
Kernel-Level Checker
Inspects system memory, processes, drivers, and system-level indicators.
Detects kernel-mode cheats, suspicious drivers, and injection vectors.
"""

import os
import platform
import subprocess
import re
from typing import List, Dict

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# Known suspicious driver names
SUSPICIOUS_DRIVERS = {
    "capcom.sys": {"severity": "critical", "desc": "Capcom.sys - known kernel exploit driver"},
    "dbk64.sys": {"severity": "critical", "desc": "Cheat Engine kernel driver"},
    "dbk32.sys": {"severity": "critical", "desc": "Cheat Engine kernel driver (32-bit)"},
    "processhacker.sys": {"severity": "critical", "desc": "Process Hacker kernel driver"},
    "kprocesshacker.sys": {"severity": "critical", "desc": "Process Hacker kernel driver"},
    "procexp.sys": {"severity": "medium", "desc": "Process Explorer kernel driver"},
    "kdmapper.sys": {"severity": "critical", "desc": "KDMapper - kernel driver mapper"},
    "iqvw64e.sys": {"severity": "critical", "desc": "Intel vulnerability driver (used for mapping)"},
    "winring0x64.sys": {"severity": "high", "desc": "WinRing0 - hardware access driver"},
    "hwinfo64.sys": {"severity": "low", "desc": "HWiNFO driver"},
    "cpuz.sys": {"severity": "low", "desc": "CPU-Z driver"},
    "gpuz.sys": {"severity": "low", "desc": "GPU-Z driver"},
    "exploit.sys": {"severity": "critical", "desc": "Suspicious exploit driver"},
    "vulnerable.sys": {"severity": "critical", "desc": "Vulnerable driver"},
    "rtcore64.sys": {"severity": "critical", "desc": "MSI Afterburner driver (exploitable)"},
    "gdrv.sys": {"severity": "critical", "desc": "Gigabyte vulnerable driver"},
    "aswarppot.sys": {"severity": "critical", "desc": "ASUS vulnerable driver"},
}


def get_loaded_drivers() -> List[Dict]:
    """Get list of currently loaded kernel drivers."""
    drivers = []

    if platform.system() != "Windows":
        # Linux: read /proc/modules
        try:
            with open("/proc/modules", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if parts:
                        drivers.append({
                            "name": parts[0],
                            "size": int(parts[1]) if len(parts) > 1 else 0,
                            "used_by": parts[3] if len(parts) > 3 else "",
                        })
        except Exception:
            pass
        return drivers

    # Windows: use driverquery
    try:
        output = subprocess.check_output(
            ["driverquery", "/FO", "CSV", "/V"],
            text=True, timeout=30, stderr=subprocess.DEVNULL
        )

        lines = output.strip().split("\n")
        if len(lines) > 1:
            for line in lines[1:]:
                parts = line.strip().split('","')
                if len(parts) >= 6:
                    name = parts[0].strip('"')
                    display_name = parts[1].strip('"') if len(parts) > 1 else ""
                    driver_type = parts[3].strip('"') if len(parts) > 3 else ""
                    state = parts[4].strip('"') if len(parts) > 4 else ""
                    start_mode = parts[5].strip('"') if len(parts) > 5 else ""

                    drivers.append({
                        "name": name,
                        "display_name": display_name,
                        "type": driver_type,
                        "state": state,
                        "start_mode": start_mode,
                    })
    except Exception:
        pass

    # Also check System32\drivers directory
    try:
        drivers_dir = os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "System32", "drivers")
        if os.path.isdir(drivers_dir):
            for f in os.listdir(drivers_dir):
                if f.lower().endswith(".sys"):
                    fpath = os.path.join(drivers_dir, f)
                    stat = os.stat(fpath)
                    drivers.append({
                        "name": f,
                        "path": fpath,
                        "size": stat.st_size,
                        "type": "file",
                    })
    except Exception:
        pass

    return drivers


def check_suspicious_drivers() -> List[Dict]:
    """Check loaded drivers against suspicious driver list."""
    flagged = []
    drivers = get_loaded_drivers()

    for driver in drivers:
        name = driver.get("name", "").lower()
        # Check exact match
        if name in SUSPICIOUS_DRIVERS:
            info = SUSPICIOUS_DRIVERS[name]
            flagged.append({
                **driver,
                "suspicious": True,
                "severity": info["severity"],
                "reason": info["desc"],
            })
        # Check partial match for .sys files
        elif name.endswith(".sys"):
            for sus_name, info in SUSPICIOUS_DRIVERS.items():
                if sus_name.replace(".sys", "") in name:
                    flagged.append({
                        **driver,
                        "suspicious": True,
                        "severity": info["severity"],
                        "reason": info["desc"],
                    })
                    break

    return flagged


def check_system_integrity() -> Dict:
    """Check system integrity indicators."""
    result = {
        "debug_mode": False,
        "test_signing": False,
        "secure_boot": None,
        "hypervisor": None,
        "error": None,
    }

    if platform.system() != "Windows":
        result["error"] = "System integrity check only available on Windows"
        return result

    # Check boot configuration
    try:
        output = subprocess.check_output(
            ["bcdedit", "/enum"],
            text=True, timeout=15, stderr=subprocess.DEVNULL
        )

        if "debug" in output.lower() and "yes" in output.lower():
            result["debug_mode"] = True

        if "testsigning" in output.lower() and "yes" in output.lower():
            result["test_signing"] = True

    except Exception:
        pass

    # Check Secure Boot
    try:
        output = subprocess.check_output(
            ["powershell", "-Command", "Confirm-SecureBootUEFI"],
            text=True, timeout=10, stderr=subprocess.DEVNULL
        )
        result["secure_boot"] = "true" in output.lower()
    except Exception:
        result["secure_boot"] = None

    return result


def get_memory_info() -> Dict:
    """Get system memory information."""
    info = {
        "total_gb": 0,
        "available_gb": 0,
        "used_percent": 0,
        "suspicious_allocations": [],
    }

    if HAS_PSUTIL:
        mem = psutil.virtual_memory()
        info["total_gb"] = round(mem.total / (1024**3), 2)
        info["available_gb"] = round(mem.available / (1024**3), 2)
        info["used_percent"] = mem.percent

    return info


def check_services() -> List[Dict]:
    """Check Windows services for suspicious entries."""
    suspicious = []

    if platform.system() != "Windows":
        return suspicious

    try:
        output = subprocess.check_output(
            ["sc", "query", "state=", "all"],
            text=True, timeout=30, stderr=subprocess.DEVNULL
        )

        current_service = {}
        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                if current_service:
                    name = current_service.get("name", "").lower()
                    for sus_driver in SUSPICIOUS_DRIVERS:
                        base = sus_driver.replace(".sys", "")
                        if base in name:
                            current_service["suspicious"] = True
                            current_service["reason"] = SUSPICIOUS_DRIVERS[sus_driver]["desc"]
                            suspicious.append(current_service)
                            break
                current_service = {"name": line.split(":", 1)[1].strip()}
            elif line.startswith("STATE"):
                state_match = re.search(r"\d+\s+(\w+)", line)
                if state_match:
                    current_service["state"] = state_match.group(1)

    except Exception:
        pass

    return suspicious


def full_kernel_check() -> Dict:
    """Complete kernel-level security check."""
    drivers = get_loaded_drivers()
    suspicious_drivers = check_suspicious_drivers()
    integrity = check_system_integrity()
    memory = get_memory_info()
    services = check_services()

    return {
        "drivers": {
            "total_loaded": len(drivers),
            "suspicious": suspicious_drivers,
            "suspicious_count": len(suspicious_drivers),
        },
        "system_integrity": integrity,
        "memory": memory,
        "suspicious_services": services,
        "summary": {
            "total_drivers": len(drivers),
            "suspicious_drivers": len(suspicious_drivers),
            "debug_mode": integrity.get("debug_mode", False),
            "test_signing": integrity.get("test_signing", False),
            "suspicious_services": len(services),
        }
    }
