"""
Build script for SS Tools Native
Creates a standalone .exe with embedded GUI (pywebview) — no browser needed.
"""

import os
import sys
import subprocess


def build():
    print("=" * 60)
    print("  SS Tools Native - Build Script")
    print("  Desktop App (pywebview) + Web fallback")
    print("=" * 60)

    # Check PyInstaller
    try:
        import PyInstaller
        print(f"[OK] PyInstaller {PyInstaller.__version__}")
    except ImportError:
        print("[!] Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    # Check pywebview
    try:
        import webview
        print(f"[OK] pywebview {webview.__version__}")
    except ImportError:
        print("[!] Installing pywebview...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pywebview"])

    # Determine platform-specific flags
    sep = ";" if sys.platform == "win32" else ":"
    windowed = "--windowed" if sys.platform == "win32" else "--console"

    hidden_imports = [
        "flask", "flask_cors", "psutil", "webview",
        "scanner", "scanner.cheat_detector", "scanner.jar_inspector",
        "scanner.minecraft_scanner", "scanner.deleted_files",
        "scanner.process_scanner", "scanner.chrome_scanner",
        "scanner.kernel_checker", "scanner.string_scanner",
    ]

    # Windows-specific: pywebview uses EdgeChromium
    if sys.platform == "win32":
        hidden_imports.extend([
            "webview.platforms.edgechromium",
            "clr", "pythonnet",
        ])

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=SS-Tools-Native",
        "--onefile",
        windowed,
        f"--add-data=templates{sep}templates",
        f"--add-data=static{sep}static",
        f"--add-data=scanner{sep}scanner",
    ]

    for hi in hidden_imports:
        cmd.append(f"--hidden-import={hi}")

    cmd.extend(["--clean", "app.py"])

    print(f"\n[*] Building with {windowed} mode...")
    print(f"[*] Command: {' '.join(cmd)}\n")

    result = subprocess.run(cmd, cwd=os.path.dirname(os.path.abspath(__file__)))

    if result.returncode == 0:
        ext = ".exe" if sys.platform == "win32" else ""
        print("\n" + "=" * 60)
        print("  BUILD SUCCESSFUL!")
        print(f"  Output: dist/SS-Tools-Native{ext}")
        print()
        print("  The app opens as a native desktop window.")
        print("  No browser needed!")
        print("=" * 60)
    else:
        print("\n[ERROR] Build failed!")
        sys.exit(1)


if __name__ == "__main__":
    build()
