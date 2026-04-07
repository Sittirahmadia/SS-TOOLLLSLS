# SS Tools Native v2.0

**Minecraft Screen Share Anti-Cheat Scanner** — A comprehensive tool for detecting cheats, macros, injectors, and suspicious activity on a player's PC during screen sharing sessions.

Supports **Minecraft 1.21 - 1.21.11** with zero false flags.

---

## Features

### Mod Scanner
- Upload `.jar` / `.zip` mod files (up to **10 GB** per batch)
- Deep inspection of every `.class` file inside JARs
- Extracts strings from Java constant pool for signature matching
- **Mod Authenticity Verification** — detects cheats disguised as whitelisted mods (e.g., a cheat renamed to `sodium-0.5.jar` is caught because its internal package structure doesn't match the real Sodium mod)

### JAR Inspector
- Full deep inspection of a single JAR file
- Lists all `.class` files, text files, resources
- Reads `fabric.mod.json`, `mcmod.info`, `MANIFEST.MF`
- Extracts and scans all string constants from Java bytecode

### Deleted File Scanner
- **Recycle Bin** — reads `$I` info files to find original paths and deletion times
- **Prefetch** — finds traces of previously executed programs (survives deletion)
- **Temp directories** — scans for suspicious `.jar`, `.exe`, `.dll` files
- **Recent files** — checks Windows recent file history
- Auto-scans on launch — detects files deleted before opening this tool

### Process Scanner
- Scans all running processes via psutil / tasklist
- Detects injectors (Process Hacker, Extreme Injector, Xenos)
- Detects macro tools (198Macro, ZenithMacro, Crystal Macro)
- Detects cheat clients running as standalone processes
- Checks Java process arguments for cheat client names
- **Hidden process detection** — compares psutil, tasklist, and WMIC results
- **DLL injection check** — scans loaded DLLs in Java/Minecraft processes

### Browser History Scanner
- Reads Chrome, Edge, Brave, and Vivaldi browsing history
- Scans URLs and downloads for cheat-related websites
- Detects downloads of known cheat clients and macro tools

### Kernel-Level Checker
- Lists all loaded kernel drivers
- Detects exploit drivers (Capcom.sys, dbk64.sys, KDMapper, etc.)
- Checks system integrity (debug mode, test signing)
- Scans Windows services for suspicious entries
- Reports system memory information

### String / Binary Scanner
- Scans common directories (Downloads, Desktop, AppData, Temp)
- Detects 198Macro, ZenithMacro, injectors, and hidden tools
- Extracts ASCII and UTF-16 strings from binary files
- Detects DLL injection API usage patterns

### Full Auto Scan
- Runs ALL scan modules automatically in sequence
- Generates comprehensive report with verdict (CLEAN / FLAGGED)
- Progress tracking with real-time updates

---

## Anti-False-Flag System

1. **Whitelist with Verification** — 100+ legitimate mods are whitelisted, but every JAR is still deep-inspected. Whitelisted status is only confirmed after verifying the internal package structure matches the expected mod.

2. **Mod Authenticity Fingerprints** — Each whitelisted mod has registered package prefixes. If someone renames `meteor-client.jar` to `sodium-0.5.jar`, the scanner detects that it has `meteordevelopment/meteorclient/` classes instead of `me/jellysquid/mods/sodium/` classes, and flags it as **DISGUISED**.

3. **Minimum Match Threshold** — Each cheat signature requires a minimum number of pattern matches before flagging. This prevents single innocent strings from triggering false positives.

---

## Supported Launchers

Auto-detects and scans mods from ALL major launchers:

| Launcher | Launcher | Launcher |
|----------|----------|----------|
| Official Minecraft | MultiMC | Prism Launcher |
| PolyMC | Lunar Client | Badlion Client |
| Feather Client | CurseForge | Modrinth |
| ATLauncher | GDLauncher | TLauncher |
| Salwyrr | Technic | SKLauncher |
| Fabric | Forge | |

---

## Detected Cheat Categories

| Category | Examples |
|----------|---------|
| Crystal PvP | AutoCrystal, AnchorMacro, BedAura, Surround |
| Sword PvP | AimAssist, KillAura, Triggerbot, Reach, Velocity |
| Movement | Speed, Fly, NoFall, Spider, Jesus, ElytraFly |
| Visual | ESP, Tracers, Xray, Nametags, Fullbright |
| Player | Scaffold, Nuker, AutoTotem, ChestStealer, Timer |
| Network | PacketFly, Blink/FakeLag, Disabler |
| Cheat Clients | Meteor, Wurst, Future, Impact, Aristois, LiquidBounce, Sigma, RusherHack, ThunderHack, Konas, Phobos, GameSense, 3arthh4ck, Salhack, ForgeHax, BleachHack, CoffeeClient, and more |
| Macro Tools | 198Macro, ZenithMacro, Crystal Macro |
| Injection | DLL Injector, Process Hacker, Cheat Engine |
| Evasion | Disguised mods, HideToolz, Process Hider |

**63 cheat signatures** with strict matching to avoid false flags.

---

## Installation

### Run from Source (Python)

```bash
# Clone
git clone https://github.com/YOUR_USER/ss-tools-native.git
cd ss-tools-native

# Install dependencies
pip install -r requirements.txt

# Run
python app.py
```

Open `http://localhost:8080` in your browser.

### Build as .exe (Windows)

```bash
python build.py
```

Output: `dist/SS-Tools-Native.exe`

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/info` | GET | App info and signature count |
| `/api/signatures` | GET | List all cheat signatures |
| `/api/upload-mods` | POST | Upload and scan mod files |
| `/api/upload-folder` | POST | Upload entire mods folder |
| `/api/inspect-jar` | POST | Deep inspect a single JAR |
| `/api/scan/launchers` | GET | Detect all Minecraft launchers |
| `/api/scan/deleted-files` | GET | Scan deleted files |
| `/api/scan/processes` | GET | Scan running processes |
| `/api/scan/chrome` | GET | Scan browser history |
| `/api/scan/kernel` | GET | Kernel-level check |
| `/api/scan/strings` | GET | Scan for hidden tools |
| `/api/scan/full-auto` | GET | Run all scans |
| `/api/scan/status` | GET | Get scan progress |
| `/api/scan/results` | GET | Get scan results |
| `/api/analyze-text` | POST | Analyze pasted text |

---

## Tech Stack

- **Backend:** Python, Flask, psutil
- **Frontend:** Vanilla HTML/CSS/JS (single-file, no build step)
- **Packaging:** PyInstaller for .exe
- **Detection:** Custom signature engine with Java bytecode string extraction

---

## License

MIT
