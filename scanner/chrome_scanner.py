"""
Chrome History Scanner
Reads Chrome browsing history to find cheat-related downloads and visits.
"""

import os
import platform
import sqlite3
import shutil
import tempfile
import datetime
from typing import List, Dict


# URLs and keywords associated with Minecraft cheats
SUSPICIOUS_URL_PATTERNS = [
    # Cheat clients
    "meteorclient.com", "wurstclient.net", "impactclient.net",
    "aristois.net", "liquidbounce.net", "sigmaclient.info",
    "rusherhack.org", "futureclient.net",
    # Macro tools
    "198macro", "zenithmacro", "crystalmacro",
    # Generic cheat sites
    "minecrafthacks", "minecraft-hacks", "hackphoenix",
    "wizardhax.com", "cheating.net", "mc-hacks",
    # Download sites for cheats
    "mediafire.com/file.*macro", "mediafire.com/file.*hack",
    "mediafire.com/file.*cheat", "mediafire.com/file.*client",
    "mega.nz.*macro", "mega.nz.*hack",
    "anonfiles.com.*macro", "anonfiles.com.*hack",
    # Forums
    "mpgh.net/forum/minecraft",
    "unknowncheats.me/minecraft",
    # GitHub cheat repos
    "github.com.*meteor-client",
    "github.com.*wurst",
    "github.com.*bleachhack",
    "github.com.*rusherhack",
]

SUSPICIOUS_DOWNLOAD_PATTERNS = [
    "198macro", "zenithmacro", "crystalmacro", "autoclicker",
    "meteor-client", "wurst", "impact", "aristois", "liquidbounce",
    "sigma", "rusherhack", "futureclient", "phobos", "konas",
    "gamesense", "earthhack", "salhack", "forgehax", "bleachhack",
    "thunderhack", "coffeeclient", "injector", "cheatengine",
    "processhacker", "extremeinjector", "xenos",
    "aimassist", "killaura", "triggerbot",
]


def get_chrome_profile_paths() -> List[str]:
    """Get all Chrome profile paths."""
    paths = []

    if platform.system() == "Windows":
        base = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data")
    elif platform.system() == "Darwin":
        base = os.path.expanduser("~/Library/Application Support/Google/Chrome")
    else:
        base = os.path.expanduser("~/.config/google-chrome")

    if os.path.isdir(base):
        # Default profile
        default = os.path.join(base, "Default")
        if os.path.isdir(default):
            paths.append(default)

        # Additional profiles
        for item in os.listdir(base):
            if item.startswith("Profile "):
                profile_path = os.path.join(base, item)
                if os.path.isdir(profile_path):
                    paths.append(profile_path)

    # Also check other Chromium-based browsers
    chromium_bases = []
    if platform.system() == "Windows":
        local = os.environ.get("LOCALAPPDATA", "")
        chromium_bases = [
            os.path.join(local, "Microsoft", "Edge", "User Data"),
            os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"),
            os.path.join(local, "Vivaldi", "User Data"),
            os.path.join(local, "Opera Software", "Opera Stable"),
        ]
    elif platform.system() == "Linux":
        config = os.path.expanduser("~/.config")
        chromium_bases = [
            os.path.join(config, "microsoft-edge"),
            os.path.join(config, "BraveSoftware", "Brave-Browser"),
            os.path.join(config, "vivaldi"),
            os.path.join(config, "chromium"),
        ]

    for base in chromium_bases:
        if os.path.isdir(base):
            default = os.path.join(base, "Default")
            if os.path.isdir(default):
                paths.append(default)

    return paths


def read_chrome_history(profile_path: str, max_results: int = 5000) -> List[Dict]:
    """Read Chrome browsing history from a profile."""
    history = []
    db_path = os.path.join(profile_path, "History")

    if not os.path.isfile(db_path):
        return history

    # Copy database to avoid lock issues
    tmp = tempfile.mktemp(suffix=".db")
    try:
        shutil.copy2(db_path, tmp)

        conn = sqlite3.connect(tmp)
        cursor = conn.cursor()

        # Get URLs with visit time
        cursor.execute("""
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT ?
        """, (max_results,))

        for row in cursor.fetchall():
            url, title, visit_count, last_visit = row
            # Convert Chrome timestamp (microseconds since 1601-01-01)
            try:
                timestamp = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=last_visit)
                visit_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                visit_time = "Unknown"

            history.append({
                "url": url,
                "title": title or "",
                "visit_count": visit_count,
                "last_visit": visit_time,
            })

        conn.close()
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

    return history


def read_chrome_downloads(profile_path: str, max_results: int = 2000) -> List[Dict]:
    """Read Chrome download history."""
    downloads = []
    db_path = os.path.join(profile_path, "History")

    if not os.path.isfile(db_path):
        return downloads

    tmp = tempfile.mktemp(suffix=".db")
    try:
        shutil.copy2(db_path, tmp)
        conn = sqlite3.connect(tmp)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT target_path, tab_url, total_bytes, start_time, end_time
            FROM downloads
            ORDER BY start_time DESC
            LIMIT ?
        """, (max_results,))

        for row in cursor.fetchall():
            target, tab_url, size, start, end = row
            try:
                timestamp = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=start)
                start_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                start_time = "Unknown"

            downloads.append({
                "file_path": target,
                "filename": os.path.basename(target) if target else "",
                "source_url": tab_url or "",
                "size_mb": round(size / (1024 * 1024), 2) if size else 0,
                "download_time": start_time,
            })

        conn.close()
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

    return downloads


def scan_chrome_history() -> Dict:
    """Full Chrome history scan for cheat-related activity."""
    profiles = get_chrome_profile_paths()

    result = {
        "profiles_found": len(profiles),
        "suspicious_urls": [],
        "suspicious_downloads": [],
        "total_urls_scanned": 0,
        "total_downloads_scanned": 0,
        "error": None,
    }

    if not profiles:
        result["error"] = "No Chrome/Chromium profiles found"
        return result

    for profile in profiles:
        # Scan history
        history = read_chrome_history(profile)
        result["total_urls_scanned"] += len(history)

        for entry in history:
            url_lower = entry["url"].lower()
            title_lower = entry["title"].lower()

            for pattern in SUSPICIOUS_URL_PATTERNS:
                if pattern.lower() in url_lower or pattern.lower() in title_lower:
                    entry["matched_pattern"] = pattern
                    entry["profile"] = profile
                    result["suspicious_urls"].append(entry)
                    break

        # Scan downloads
        downloads = read_chrome_downloads(profile)
        result["total_downloads_scanned"] += len(downloads)

        for dl in downloads:
            filename_lower = (dl.get("filename") or "").lower()
            url_lower = (dl.get("source_url") or "").lower()

            for pattern in SUSPICIOUS_DOWNLOAD_PATTERNS:
                if pattern.lower() in filename_lower or pattern.lower() in url_lower:
                    dl["matched_pattern"] = pattern
                    dl["profile"] = profile
                    result["suspicious_downloads"].append(dl)
                    break

    return result
