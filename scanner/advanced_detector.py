"""
Advanced Detector - Fast, Parallel Cheat Detection
- No hangs or timeouts
- Parallel scanning with proper threading
- Detailed JAR/Class file inspection
- DLL and injector detection
- Enhanced cheat signatures
"""

import os
import json
import threading
import time
import zipfile
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from dataclasses import dataclass


@dataclass
class DetectionResult:
    filename: str
    file_path: str
    file_type: str  # jar, class, dll
    is_cheat: bool
    risk_level: str  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    detected_cheats: List[str]
    class_files: List[str]
    dll_suspicious: List[str]
    details: Dict


# Enhanced cheat detection patterns
ENHANCED_CHEAT_PATTERNS = {
    # Core cheat clients
    "phobos": {"type": "client", "risk": "CRITICAL", "dll": False},
    "impact": {"type": "client", "risk": "CRITICAL", "dll": False},
    "wurst": {"type": "client", "risk": "CRITICAL", "dll": False},
    "future": {"type": "client", "risk": "CRITICAL", "dll": False},
    "sigma": {"type": "client", "risk": "CRITICAL", "dll": False},
    
    # Pathfinding bots
    "baritone": {"type": "bot", "risk": "CRITICAL", "dll": False},
    "pathing": {"type": "bot", "risk": "HIGH", "dll": False},
    "pathfinder": {"type": "bot", "risk": "HIGH", "dll": False},
    
    # Vision cheats
    "xray": {"type": "vision", "risk": "CRITICAL", "dll": False},
    "esp": {"type": "vision", "risk": "CRITICAL", "dll": False},
    "radar": {"type": "vision", "risk": "CRITICAL", "dll": False},
    "orefinder": {"type": "vision", "risk": "HIGH", "dll": False},
    "entityesp": {"type": "vision", "risk": "CRITICAL", "dll": False},
    
    # Combat cheats
    "killaura": {"type": "combat", "risk": "CRITICAL", "dll": False},
    "aimbot": {"type": "combat", "risk": "CRITICAL", "dll": False},
    "autoclicker": {"type": "combat", "risk": "CRITICAL", "dll": False},
    "reach": {"type": "combat", "risk": "HIGH", "dll": False},
    "knockback": {"type": "combat", "risk": "HIGH", "dll": False},
    "forcefield": {"type": "combat", "risk": "CRITICAL", "dll": False},
    
    # Movement cheats
    "speed": {"type": "movement", "risk": "HIGH", "dll": False},
    "flight": {"type": "movement", "risk": "CRITICAL", "dll": False},
    "noclip": {"type": "movement", "risk": "CRITICAL", "dll": False},
    "elytrafly": {"type": "movement", "risk": "HIGH", "dll": False},
    "nofall": {"type": "movement", "risk": "MEDIUM", "dll": False},
    
    # Building cheats
    "schematica": {"type": "builder", "risk": "HIGH", "dll": False},
    "litematica": {"type": "builder", "risk": "HIGH", "dll": False},
    "scaffold": {"type": "builder", "risk": "HIGH", "dll": False},
    
    # Macro/Automation
    "macro": {"type": "macro", "risk": "MEDIUM", "dll": False},
    "automation": {"type": "macro", "risk": "MEDIUM", "dll": False},
    "automate": {"type": "macro", "risk": "MEDIUM", "dll": False},
    
    # Injector detection (Java)
    "transformer": {"type": "injector", "risk": "CRITICAL", "dll": False},
    "asm-": {"type": "injector", "risk": "CRITICAL", "dll": False},
    "javassist": {"type": "injector", "risk": "CRITICAL", "dll": False},
    "bytebuddy": {"type": "injector", "risk": "CRITICAL", "dll": False},
    
    # DLL injectors (Windows)
    "DllInject": {"type": "dll_injector", "risk": "CRITICAL", "dll": True},
    "dll_inject": {"type": "dll_injector", "risk": "CRITICAL", "dll": True},
    "hook": {"type": "dll_injector", "risk": "HIGH", "dll": True},
    "detour": {"type": "dll_injector", "risk": "HIGH", "dll": True},
    "minhook": {"type": "dll_injector", "risk": "HIGH", "dll": True},
    
    # Mining/Cryptojacking
    "xmrig": {"type": "miner", "risk": "HIGH", "dll": False},
    "mining": {"type": "miner", "risk": "HIGH", "dll": False},
    "monero": {"type": "miner", "risk": "HIGH", "dll": False},
    
    # Render/Texture abuse
    "render": {"type": "render", "risk": "MEDIUM", "dll": False},
    "texture": {"type": "render", "risk": "MEDIUM", "dll": False},
    "wireframe": {"type": "render", "risk": "MEDIUM", "dll": False},
}

# Suspicious package names
SUSPICIOUS_PACKAGES = {
    "net.raphimc", "com.github.cabaletta", "com.github.Equim_chan",
    "baritone", "phobos", "impact", "wurst", "sigma",
    "top.theillusivec4.curios", "dev.tr7zw.AttributeStorage",
}

# Suspicious class patterns
SUSPICIOUS_CLASS_PATTERNS = {
    "EventBus", "Hook", "Inject", "Transform", "ASM",
    "MethodHandle", "LambdaMetafactory", "Unsafe", "Reflection",
    "GetField", "PutField", "InvokeVirtual", "InvokeStatic"
}


def extract_strings_from_class(class_bytes: bytes) -> List[str]:
    """Extract strings from Java class file (basic)."""
    strings = []
    try:
        # Look for string constants in bytecode
        for i in range(len(class_bytes) - 1):
            byte = class_bytes[i:i+1]
            if 32 <= ord(byte) <= 126:  # Printable ASCII
                j = i
                temp_str = ""
                while j < len(class_bytes) and 32 <= ord(class_bytes[j:j+1]) <= 126:
                    temp_str += class_bytes[j:j+1].decode('ascii', errors='ignore')
                    j += 1
                
                if len(temp_str) > 3:
                    strings.append(temp_str)
                    i = j
    except Exception:
        pass
    
    return strings


def scan_jar_fast(jar_path: str, timeout: int = 10) -> DetectionResult:
    """Fast JAR scanning with timeout."""
    start_time = time.time()
    filename = os.path.basename(jar_path)
    detected_cheats = []
    class_files = []
    details = {
        "jar_size": os.path.getsize(jar_path),
        "classes_scanned": 0,
        "strings_found": 0,
        "suspicious_packages": [],
        "files_inside": []
    }
    
    try:
        with zipfile.ZipFile(jar_path, 'r') as zf:
            # Get all files
            all_files = zf.namelist()
            details["files_inside"] = all_files[:500]  # Limit to 500 for performance
            
            # Scan JAR metadata
            for entry in all_files:
                if time.time() - start_time > timeout:
                    break
                
                entry_lower = entry.lower()
                
                # Check for suspicious packages
                for suspicious_pkg in SUSPICIOUS_PACKAGES:
                    if suspicious_pkg in entry_lower:
                        details["suspicious_packages"].append(entry)
                        break
                
                # Check file names for cheats
                for cheat_pattern in ENHANCED_CHEAT_PATTERNS.keys():
                    if cheat_pattern in entry_lower:
                        detected_cheats.append(f"{cheat_pattern} (in {entry})")
                        break
                
                # Extract class files
                if entry.endswith(".class"):
                    class_files.append(entry)
                    details["classes_scanned"] += 1
                    
                    # Sample scan first few class files
                    if details["classes_scanned"] <= 50:
                        try:
                            class_bytes = zf.read(entry)
                            strings = extract_strings_from_class(class_bytes)
                            details["strings_found"] += len(strings)
                            
                            # Check strings for cheats
                            for string in strings:
                                string_lower = string.lower()
                                for cheat_pattern in ENHANCED_CHEAT_PATTERNS.keys():
                                    if cheat_pattern in string_lower:
                                        detected_cheats.append(f"{cheat_pattern} (in string)")
                                        break
                        except Exception:
                            pass
    except Exception as e:
        details["error"] = str(e)
    
    # Determine risk level
    risk_level = "NONE"
    if detected_cheats:
        critical_count = sum(1 for c in detected_cheats if "CRITICAL" in str(ENHANCED_CHEAT_PATTERNS.get(c.split()[0], {})))
        risk_level = "CRITICAL" if critical_count > 0 else "HIGH"
    
    return DetectionResult(
        filename=filename,
        file_path=jar_path,
        file_type="jar",
        is_cheat=len(detected_cheats) > 0,
        risk_level=risk_level,
        detected_cheats=detected_cheats,
        class_files=class_files,
        dll_suspicious=[],
        details=details
    )


def scan_class_fast(class_path: str, timeout: int = 5) -> DetectionResult:
    """Fast CLASS file scanning."""
    filename = os.path.basename(class_path)
    detected_cheats = []
    details = {
        "file_size": os.path.getsize(class_path),
        "strings_found": 0,
        "strings": []
    }
    
    try:
        with open(class_path, 'rb') as f:
            class_bytes = f.read()
            strings = extract_strings_from_class(class_bytes)
            details["strings_found"] = len(strings)
            details["strings"] = strings[:100]
            
            for string in strings:
                string_lower = string.lower()
                for cheat_pattern in ENHANCED_CHEAT_PATTERNS.keys():
                    if cheat_pattern in string_lower:
                        detected_cheats.append(f"{cheat_pattern}")
                        break
    except Exception as e:
        details["error"] = str(e)
    
    risk_level = "CRITICAL" if detected_cheats else "NONE"
    
    return DetectionResult(
        filename=filename,
        file_path=class_path,
        file_type="class",
        is_cheat=len(detected_cheats) > 0,
        risk_level=risk_level,
        detected_cheats=detected_cheats,
        class_files=[],
        dll_suspicious=[],
        details=details
    )


def scan_dll_fast(dll_path: str) -> DetectionResult:
    """Fast DLL scanning for hooks and injectors."""
    filename = os.path.basename(dll_path)
    detected_cheats = []
    suspicious_dlls = []
    
    try:
        with open(dll_path, 'rb') as f:
            dll_bytes = f.read()
            
            # Extract strings
            for i in range(len(dll_bytes) - 1):
                byte = dll_bytes[i:i+1]
                if 32 <= ord(byte) <= 126:
                    j = i
                    temp_str = ""
                    while j < len(dll_bytes) and 32 <= ord(dll_bytes[j:j+1]) <= 126 and j - i < 100:
                        temp_str += dll_bytes[j:j+1].decode('ascii', errors='ignore')
                        j += 1
                    
                    if len(temp_str) > 5:
                        temp_lower = temp_str.lower()
                        for cheat_pattern in ENHANCED_CHEAT_PATTERNS.keys():
                            if ENHANCED_CHEAT_PATTERNS[cheat_pattern].get("dll"):
                                if cheat_pattern in temp_lower:
                                    detected_cheats.append(cheat_pattern)
                                    suspicious_dlls.append(temp_str)
                                    break
    except Exception:
        pass
    
    risk_level = "CRITICAL" if detected_cheats else "NONE"
    
    return DetectionResult(
        filename=filename,
        file_path=dll_path,
        file_type="dll",
        is_cheat=len(detected_cheats) > 0,
        risk_level=risk_level,
        detected_cheats=detected_cheats,
        class_files=[],
        dll_suspicious=suspicious_dlls,
        details={}
    )


def parallel_scan_mods(mod_paths: List[str], max_workers: int = 8, timeout: int = 60) -> List[DetectionResult]:
    """Scan multiple mods in parallel with timeout."""
    results = []
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        
        for mod_path in mod_paths:
            if time.time() - start_time > timeout:
                break
            
            ext = os.path.splitext(mod_path)[1].lower()
            
            if ext == ".jar":
                future = executor.submit(scan_jar_fast, mod_path, timeout=10)
            elif ext == ".class":
                future = executor.submit(scan_class_fast, mod_path, timeout=5)
            elif ext == ".dll":
                future = executor.submit(scan_dll_fast, mod_path)
            else:
                continue
            
            futures[future] = mod_path
        
        for future in as_completed(futures):
            try:
                result = future.result(timeout=15)
                results.append(result)
            except TimeoutError:
                mod_path = futures[future]
                results.append(DetectionResult(
                    filename=os.path.basename(mod_path),
                    file_path=mod_path,
                    file_type="unknown",
                    is_cheat=False,
                    risk_level="TIMEOUT",
                    detected_cheats=[],
                    class_files=[],
                    dll_suspicious=[],
                    details={"error": "Scan timeout"}
                ))
            except Exception as e:
                mod_path = futures[future]
                results.append(DetectionResult(
                    filename=os.path.basename(mod_path),
                    file_path=mod_path,
                    file_type="unknown",
                    is_cheat=False,
                    risk_level="ERROR",
                    detected_cheats=[],
                    class_files=[],
                    dll_suspicious=[],
                    details={"error": str(e)}
                ))
    
    return results


def format_result_for_json(result: DetectionResult) -> Dict:
    """Format result for JSON response."""
    return {
        "filename": result.filename,
        "file_path": result.file_path,
        "file_type": result.file_type,
        "is_cheat": result.is_cheat,
        "risk_level": result.risk_level,
        "detected_cheats": result.detected_cheats,
        "class_files": result.class_files,
        "dll_suspicious": result.dll_suspicious,
        "details": result.details
    }
