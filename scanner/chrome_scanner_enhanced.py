"""
Enhanced Chrome & Browser History Scanner
- Scans browser history for visited websites
- Detects adult/pornographic content websites
- Tracks social media, streaming, gaming sites
- Identifies suspicious activity patterns
"""

import os
import sqlite3
import json
import platform
import shutil
from typing import List, Dict
from pathlib import Path
from datetime import datetime, timedelta


# Adult/Pornographic website domains
ADULT_DOMAINS = {
    "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com", "youporn.com",
    "xhamster.com", "spankbang.com", "pornoxo.com", "beeg.com", "porno.com",
    "tube8.com", "xtube.com", "slutload.com", "extremetube.com", "thumbzilla.com",
    "theporndude.com", "porndig.com", "pornerbros.com", "tubepornclassic.com",
    "4tube.com", "xxx.com", "livejasmin.com", "myfreecams.com", "chaturbate.com",
    "cam4.com", "camsoda.com", "flirt4free.com", "xmatch.com", "adultfriendfinder.com",
    "ifeelmyself.com", "lustfulvideos.com", "sexyflix.com", "video.severin.su",
    "bokep.com", "bokepindo.net", "bokepbarat.com", "situs bokep", "jav", "javhdporn",
}

# Suspicious domains for different categories
STREAMING_SITES = {
    "netflix.com", "hulu.com", "disney.com", "hbomax.com", "primevideo.com",
    "peacocktv.com", "paramountplus.com", "crunchyroll.com", "animixplay.com",
}

SOCIAL_MEDIA_SITES = {
    "facebook.com", "twitter.com", "instagram.com", "tiktok.com", "reddit.com",
    "snapchat.com", "discord.com", "telegram.org", "whatsapp.com",
}

GAMING_SITES = {
    "twitch.tv", "youtube.com", "steam.com", "epicgames.com", "roblox.com",
    "minecraft.net", "itch.io", "betterhelp.com", "g2a.com",
}

SUSPICIOUS_PATTERNS = {
    "cheat sites": ["cheatengine", "megaman", "noclip", "speedhack", "trainer"],
    "hacks": ["hack", "crack", "keygen", "warez", "torrent"],
    "mining": ["cryptocurrency", "mining", "bitcoin", "monero", "mining pool"],
}


def get_chrome_profile_path() -> List[str]:
    """Get Chrome/Chromium profile paths."""
    paths = []

    if platform.system() == "Windows":
        base = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data")
        if os.path.exists(base):
            for profile in os.listdir(base):
                profile_path = os.path.join(base, profile)
                if os.path.isdir(profile_path):
                    paths.append(profile_path)

        # Edge
        edge_base = os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data")
        if os.path.exists(edge_base):
            for profile in os.listdir(edge_base):
                profile_path = os.path.join(edge_base, profile)
                if os.path.isdir(profile_path):
                    paths.append(profile_path)

    elif platform.system() == "Darwin":  # macOS
        base = os.path.expanduser("~/Library/Application Support/Google/Chrome")
        if os.path.exists(base):
            for profile in os.listdir(base):
                profile_path = os.path.join(base, profile)
                if os.path.isdir(profile_path):
                    paths.append(profile_path)

    elif platform.system() == "Linux":
        base = os.path.expanduser("~/.config/google-chrome")
        if os.path.exists(base):
            for profile in os.listdir(base):
                profile_path = os.path.join(base, profile)
                if os.path.isdir(profile_path):
                    paths.append(profile_path)

    return paths


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Remove www
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return url.lower()


def get_chrome_history(profile_path: str) -> List[Dict]:
    """Extract Chrome history."""
    history = []
    history_db = os.path.join(profile_path, "History")

    if not os.path.exists(history_db):
        return history

    # Chrome locks the database, so we need to make a copy
    temp_db = os.path.join("/tmp", f"chrome_history_{os.getpid()}.db")
    try:
        shutil.copy2(history_db, temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        # Get last 1000 history entries
        try:
            cursor.execute("""
                SELECT url, title, visit_time FROM urls 
                ORDER BY visit_time DESC LIMIT 1000
            """)

            for row in cursor.fetchall():
                url, title, visit_time = row
                # Chrome timestamps are in microseconds since 1601
                timestamp = datetime(1601, 1, 1) + timedelta(microseconds=visit_time)

                history.append({
                    "url": url,
                    "title": title or "",
                    "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "domain": extract_domain(url)
                })
        except sqlite3.OperationalError:
            pass

        conn.close()
    except (OSError, sqlite3.Error):
        pass
    finally:
        try:
            os.remove(temp_db)
        except OSError:
            pass

    return history


def scan_chrome_history() -> Dict:
    """Scan Chrome history for suspicious/adult content."""
    results = {
        "profile_count": 0,
        "total_entries": 0,
        "adult_sites": [],
        "streaming_sites": [],
        "social_media": [],
        "suspicious_urls": [],
        "suspicious_downloads": [],
        "cheat_sites": [],
        "categories": {}
    }

    profiles = get_chrome_profile_path()
    results["profile_count"] = len(profiles)

    for profile in profiles:
        try:
            history = get_chrome_history(profile)
            results["total_entries"] += len(history)

            for entry in history:
                domain = entry["domain"]
                url_lower = entry["url"].lower()

                # Check adult sites
                for adult_domain in ADULT_DOMAINS:
                    if adult_domain in domain:
                        results["adult_sites"].append(entry)
                        break

                # Check streaming
                for stream_domain in STREAMING_SITES:
                    if stream_domain in domain:
                        results["streaming_sites"].append(entry)
                        break

                # Check social media
                for social_domain in SOCIAL_MEDIA_SITES:
                    if social_domain in domain:
                        results["social_media"].append(entry)
                        break

                # Check gaming
                for game_domain in GAMING_SITES:
                    if game_domain in domain:
                        if "twitch" not in domain and "youtube" not in domain:
                            results["categories"].setdefault("gaming", []).append(entry)
                        break

                # Check suspicious patterns
                for category, patterns in SUSPICIOUS_PATTERNS.items():
                    for pattern in patterns:
                        if pattern in url_lower:
                            results["suspicious_urls"].append({
                                **entry,
                                "reason": category,
                                "pattern": pattern
                            })

                # Check downloads
                if "download" in url_lower or "dl" in url_lower:
                    results["suspicious_downloads"].append(entry)

        except (OSError, PermissionError):
            continue

    # Remove duplicates
    results["adult_sites"] = list({e["url"]: e for e in results["adult_sites"]}.values())
    results["streaming_sites"] = list({e["url"]: e for e in results["streaming_sites"]}.values())
    results["suspicious_urls"] = list({e["url"]: e for e in results["suspicious_urls"]}.values())

    # Summary
    results["summary"] = {
        "adult_content_count": len(results["adult_sites"]),
        "streaming_count": len(results["streaming_sites"]),
        "social_media_count": len(results["social_media"]),
        "suspicious_urls_count": len(results["suspicious_urls"]),
        "risk_level": "HIGH" if len(results["adult_sites"]) > 5 or len(results["suspicious_urls"]) > 10 else "MEDIUM" if len(results["adult_sites"]) > 0 else "LOW"
    }

    return results


def get_all_browser_profiles() -> Dict:
    """Get all installed browser profiles."""
    browsers = {
        "Chrome": get_chrome_profile_path(),
        "Edge": [],
        "Firefox": []
    }

    # Firefox
    if platform.system() == "Windows":
        firefox_base = os.path.expanduser("~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
    elif platform.system() == "Darwin":
        firefox_base = os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
    else:
        firefox_base = os.path.expanduser("~/.mozilla/firefox")

    if os.path.exists(firefox_base):
        try:
            for profile in os.listdir(firefox_base):
                browsers["Firefox"].append(os.path.join(firefox_base, profile))
        except OSError:
            pass

    return browsers
