# SS Tools Native - RED EDITION .EXE BUILD

Build a standalone Windows executable with embedded red-themed GUI.

## Prerequisites

- Python 3.8+ (Windows)
- Git

## Quick Build

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
pip install PyInstaller
```

### Step 2: Build .EXE

```bash
python build_exe.py
```

The build process will:
1. Verify dependencies
2. Compile the application
3. Create `dist/SS-Tools-Native.exe`

### Step 3: Run

Double-click `SS-Tools-Native.exe` or run from command line:

```bash
dist/SS-Tools-Native.exe
```

## Features

✅ **Red-Dark Theme GUI** - Modern, professional design
✅ **Fast Scanning** - No hangs, no stuck scans
✅ **Standalone** - Single .exe file, no dependencies needed
✅ **Desktop App** - Runs as native Windows app (no browser required)
✅ **Embedded Web Server** - Flask backend runs in background

## GUI Features

- 🏠 **Home** - Quick start guide
- 🔍 **Scanner** - Fast mod detection
- ⛏️ **Minecraft** - Auto-detect launchers
- 📦 **JAR Inspector** - View file contents
- 🌐 **Browser** - Scan history for adult content
- ⚙️ **Processes** - Detect malicious processes
- 🚀 **Full Scan** - Complete system analysis

## Scan Results

All scans provide:
- ✅ Summary statistics
- 📊 Risk assessment
- 📋 Detailed reports
- 🎯 Real-time progress

## Troubleshooting

### Build takes too long
- First build may take 5-10 minutes
- Subsequent builds are faster
- Ensure you have 2GB free disk space

### .EXE won't start
- Check Windows Defender didn't quarantine it
- Run as Administrator
- Check antivirus settings

### GUI doesn't appear
- Wait 5-10 seconds for Flask backend to start
- Check if port 8080 is available

## File Size

- Uncompressed: ~200-300 MB
- Can be compressed with UPX if needed

## Red Theme Colors

- Primary Red: `#ff5252`
- Dark Background: `#0a0a0a`
- Border: `#8b0000`
- Accent: `#ff7070`

## Updates

To update the .exe:
1. Pull latest changes
2. Run `python build_exe.py` again
3. Replace old .exe with new one

---

**SS Tools Native v2.1 - Red Edition**
Fast • Accurate • Secure
