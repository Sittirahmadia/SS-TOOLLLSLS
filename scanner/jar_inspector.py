"""
JAR File Inspector
Reads .jar and .zip files, extracts .class file names,
reads text content, and runs cheat detection on contents.
"""

import os
import zipfile
import io
import struct
from typing import List, Dict, Optional
from .cheat_detector import detect_cheats, is_whitelisted, verify_mod_authenticity, DetectionResult


def read_jar_entries(jar_path: str) -> Dict:
    """
    Read a JAR/ZIP file and return its structure.
    Returns dict with class files, resources, and metadata.
    """
    result = {
        "path": jar_path,
        "filename": os.path.basename(jar_path),
        "size_mb": round(os.path.getsize(jar_path) / (1024 * 1024), 2),
        "class_files": [],
        "text_files": [],
        "resource_files": [],
        "manifest": None,
        "mod_info": None,
        "fabric_mod_json": None,
        "entries_count": 0,
        "error": None,
    }

    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            result["entries_count"] = len(zf.namelist())

            for entry in zf.namelist():
                entry_lower = entry.lower()

                if entry_lower.endswith(".class"):
                    result["class_files"].append(entry)
                elif entry_lower.endswith((".txt", ".cfg", ".conf", ".properties", ".json", ".toml", ".yml", ".yaml", ".xml", ".mcmeta", ".lang")):
                    result["text_files"].append(entry)
                else:
                    result["resource_files"].append(entry)

                # Read manifest
                if entry == "META-INF/MANIFEST.MF":
                    try:
                        result["manifest"] = zf.read(entry).decode("utf-8", errors="replace")
                    except Exception:
                        pass

                # Read mod metadata
                if entry_lower in ("mcmod.info", "mods.toml", "pack.mcmeta"):
                    try:
                        result["mod_info"] = zf.read(entry).decode("utf-8", errors="replace")
                    except Exception:
                        pass

                if entry == "fabric.mod.json":
                    try:
                        result["fabric_mod_json"] = zf.read(entry).decode("utf-8", errors="replace")
                    except Exception:
                        pass

    except zipfile.BadZipFile:
        result["error"] = "Invalid or corrupted JAR/ZIP file"
    except Exception as e:
        result["error"] = str(e)

    return result


def extract_strings_from_class(class_bytes: bytes) -> List[str]:
    """
    Extract UTF-8 string constants from a Java .class file's constant pool.
    """
    strings = []
    try:
        if len(class_bytes) < 10:
            return strings

        # Check Java magic number
        magic = struct.unpack(">I", class_bytes[:4])[0]
        if magic != 0xCAFEBABE:
            return strings

        # Skip version info
        offset = 8
        cp_count = struct.unpack(">H", class_bytes[offset:offset+2])[0]
        offset += 2

        i = 1
        while i < cp_count and offset < len(class_bytes):
            tag = class_bytes[offset]
            offset += 1

            if tag == 1:  # CONSTANT_Utf8
                if offset + 2 > len(class_bytes):
                    break
                length = struct.unpack(">H", class_bytes[offset:offset+2])[0]
                offset += 2
                if offset + length > len(class_bytes):
                    break
                try:
                    s = class_bytes[offset:offset+length].decode("utf-8", errors="replace")
                    if len(s) >= 3 and not all(c in " \t\n\r" for c in s):
                        strings.append(s)
                except Exception:
                    pass
                offset += length
            elif tag in (7, 8, 16, 19, 20):  # 2-byte refs
                offset += 2
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):  # 4-byte
                offset += 4
            elif tag in (5, 6):  # 8-byte (long, double)
                offset += 8
                i += 1  # Takes two slots
            elif tag == 15:  # MethodHandle
                offset += 3
            else:
                break
            i += 1

    except Exception:
        pass

    return strings


def inspect_jar(jar_path: str) -> Dict:
    """
    Full JAR inspection: reads structure, extracts class strings,
    and runs cheat detection on everything.
    """
    filename = os.path.basename(jar_path)
    claims_whitelisted = is_whitelisted(filename)

    # NEVER skip inspection — always read the JAR contents.
    # Cheaters rename cheat JARs to whitelisted names (e.g. "sodium-1.0.jar").
    # We verify authenticity by checking internal package structure.

    entries = read_jar_entries(jar_path)
    if entries.get("error"):
        return {
            "path": jar_path,
            "filename": filename,
            "error": entries["error"],
            "detections": [],
        }

    all_detections: List[DetectionResult] = []
    scanned_classes = 0
    all_strings_combined = []

    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            # Scan class files for cheat patterns
            for class_file in entries["class_files"]:
                try:
                    class_bytes = zf.read(class_file)
                    strings = extract_strings_from_class(class_bytes)
                    scanned_classes += 1

                    # Combine strings for scanning
                    content = " ".join(strings)
                    all_strings_combined.extend(strings)

                    # Also check class file path as content
                    content += " " + class_file

                    detections = detect_cheats(content, class_file, f"{jar_path}!/{class_file}")
                    all_detections.extend(detections)
                except Exception:
                    continue

            # Scan text files
            for text_file in entries["text_files"]:
                try:
                    text_content = zf.read(text_file).decode("utf-8", errors="replace")
                    detections = detect_cheats(text_content, text_file, f"{jar_path}!/{text_file}")
                    all_detections.extend(detections)
                except Exception:
                    continue

            # Scan manifest
            if entries["manifest"]:
                detections = detect_cheats(entries["manifest"], "MANIFEST.MF", f"{jar_path}!/META-INF/MANIFEST.MF")
                all_detections.extend(detections)

            # Scan mod metadata
            for meta_field in ["mod_info", "fabric_mod_json"]:
                if entries[meta_field]:
                    detections = detect_cheats(entries[meta_field], meta_field, f"{jar_path}!/{meta_field}")
                    all_detections.extend(detections)

    except Exception as e:
        return {
            "path": jar_path,
            "filename": filename,
            "error": str(e),
            "detections": [],
        }

    # Also run detection on the filename itself
    name_detections = detect_cheats("", filename, jar_path)
    all_detections.extend(name_detections)

    # Also run full combined string check
    combined = " ".join(all_strings_combined)
    combined_detections = detect_cheats(combined, filename, jar_path)
    # Merge without duplicates
    existing_sigs = {d.signature_name for d in all_detections}
    for d in combined_detections:
        if d.signature_name not in existing_sigs:
            all_detections.append(d)
            existing_sigs.add(d.signature_name)

    # Deduplicate detections
    seen = set()
    unique_detections = []
    for d in all_detections:
        key = (d.signature_name, d.file_path)
        if key not in seen:
            seen.add(key)
            unique_detections.append(d)

    # ── Authenticity Verification ──
    # If filename matches a whitelisted mod, verify the JAR actually
    # contains the expected package structure for that mod.
    # A cheat disguised as "sodium-1.0.jar" won't have me/jellysquid/mods/sodium classes.
    authenticity = verify_mod_authenticity(filename, entries["class_files"])
    is_disguised = False

    if claims_whitelisted and not authenticity["is_authentic"]:
        # JAR claims to be a whitelisted mod but has WRONG package structure
        is_disguised = True
        disguise_detection = DetectionResult(
            flagged=True,
            signature_name="Disguised Cheat (Fake Whitelisted Mod)",
            category="Evasion",
            severity="critical",
            description=(
                f"This JAR is named like '{authenticity['claimed_mod']}' but does NOT contain "
                f"the expected package structure. Expected packages: "
                f"{', '.join(authenticity['expected_packages'])}. "
                f"Found matching: {', '.join(authenticity['found_matching']) or 'NONE'}. "
                f"This is very likely a cheat client disguised as a legitimate mod."
            ),
            matched_patterns=[f"fake_name:{authenticity['claimed_mod']}"],
            match_count=1,
            file_path=jar_path,
            confidence=0.95,
        )
        unique_detections.insert(0, disguise_detection)

    # Determine final verdict
    flagged = len(unique_detections) > 0
    max_severity = "none"
    if flagged:
        severities = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_severity = max(unique_detections, key=lambda d: severities.get(d.severity, 0)).severity

    # Only mark as truly whitelisted if filename matches AND authenticity is verified
    # AND no cheat detections were found in the contents
    verified_whitelisted = claims_whitelisted and authenticity["is_authentic"] and not flagged

    return {
        "path": jar_path,
        "filename": filename,
        "whitelisted": verified_whitelisted,
        "safe": verified_whitelisted or not flagged,
        "flagged": flagged,
        "is_disguised": is_disguised,
        "max_severity": max_severity,
        "authenticity": {
            "claimed_mod": authenticity["claimed_mod"],
            "is_authentic": authenticity["is_authentic"],
            "expected_packages": authenticity["expected_packages"],
            "found_matching": authenticity["found_matching"],
            "confidence": authenticity["confidence"],
        } if claims_whitelisted else None,
        "class_count": len(entries["class_files"]),
        "text_count": len(entries["text_files"]),
        "resource_count": len(entries["resource_files"]),
        "scanned_classes": scanned_classes,
        "total_entries": entries["entries_count"],
        "size_mb": entries["size_mb"],
        "class_files": entries["class_files"][:200],  # Limit for display
        "detections": [
            {
                "name": d.signature_name,
                "category": d.category,
                "severity": d.severity,
                "description": d.description,
                "matched_patterns": d.matched_patterns,
                "match_count": d.match_count,
                "file": d.file_path,
                "confidence": d.confidence,
            }
            for d in unique_detections
        ],
        "manifest": entries["manifest"],
        "mod_info": entries["mod_info"],
        "fabric_mod_json": entries["fabric_mod_json"],
    }


def scan_mods_directory(mods_dir: str) -> List[Dict]:
    """Scan an entire mods directory for cheats."""
    results = []

    if not os.path.isdir(mods_dir):
        return results

    for root, dirs, files in os.walk(mods_dir):
        for f in files:
            if f.lower().endswith((".jar", ".zip")):
                fpath = os.path.join(root, f)
                try:
                    result = inspect_jar(fpath)
                    results.append(result)
                except Exception as e:
                    results.append({
                        "path": fpath,
                        "filename": f,
                        "error": str(e),
                        "detections": [],
                    })

    return results
