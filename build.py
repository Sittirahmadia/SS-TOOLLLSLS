"""
Build script for SS Tools Native
Creates a standalone .exe using PyInstaller
"""

import os
import sys
import subprocess


def build():
    print("=" * 60)
    print("  SS Tools Native - Build Script")
    print("=" * 60)

    # Check PyInstaller
    try:
        import PyInstaller
        print(f"[OK] PyInstaller {PyInstaller.__version__}")
    except ImportError:
        print("[!] Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    # Build command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=SS-Tools-Native",
        "--onefile",
        "--windowed" if sys.platform == "win32" else "--console",
        "--add-data", f"templates{os.pathsep}templates",
        "--add-data", f"static{os.pathsep}static",
        "--add-data", f"scanner{os.pathsep}scanner",
        "--hidden-import=flask",
        "--hidden-import=flask_cors",
        "--hidden-import=psutil",
        "--hidden-import=scanner",
        "--hidden-import=scanner.cheat_detector",
        "--hidden-import=scanner.jar_inspector",
        "--hidden-import=scanner.minecraft_scanner",
        "--hidden-import=scanner.deleted_files",
        "--hidden-import=scanner.process_scanner",
        "--hidden-import=scanner.chrome_scanner",
        "--hidden-import=scanner.kernel_checker",
        "--hidden-import=scanner.string_scanner",
        "--icon=NONE",
        "--clean",
        "app.py",
    ]

    print("\n[*] Building .exe ...")
    print(f"[*] Command: {' '.join(cmd)}\n")

    result = subprocess.run(cmd, cwd=os.path.dirname(os.path.abspath(__file__)))

    if result.returncode == 0:
        print("\n" + "=" * 60)
        print("  BUILD SUCCESSFUL!")
        print(f"  Output: dist/SS-Tools-Native{'.exe' if sys.platform == 'win32' else ''}")
        print("=" * 60)
    else:
        print("\n[ERROR] Build failed!")
        sys.exit(1)


if __name__ == "__main__":
    build()
