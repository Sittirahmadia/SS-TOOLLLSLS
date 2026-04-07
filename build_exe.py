"""
SS Tools Native - Build RED-THEMED .EXE
Creates standalone Windows executable with embedded red-dark GUI
"""

import os
import sys
import subprocess
import shutil


def install_deps():
    """Install required dependencies."""
    deps = [
        "PyInstaller",
        "pywebview",
        "flask",
        "flask-cors",
        "psutil",
    ]
    
    print("[*] Installing dependencies...")
    for dep in deps:
        try:
            __import__(dep.replace("-", "_"))
            print(f"[✓] {dep}")
        except ImportError:
            print(f"[+] Installing {dep}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep, "-q"])


def build_exe():
    """Build the .exe with PyInstaller."""
    
    print("\n" + "=" * 70)
    print("  SS TOOLS NATIVE - RED-THEMED .EXE BUILD")
    print("=" * 70)
    
    # Install dependencies
    install_deps()
    
    # Copy enhanced app as main entry point
    if os.path.exists("app_enhanced.py"):
        shutil.copy("app_enhanced.py", "app_main.py")
        print("[✓] Using enhanced app (app_enhanced.py)")
    else:
        shutil.copy("app.py", "app_main.py")
        print("[✓] Using standard app (app.py)")
    
    # PyInstaller command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=SS-Tools-Native",
        "--onefile",
        "--windowed",
        "--icon=NONE",
        "--add-data=templates;templates",
        "--add-data=static;static",
        "--add-data=scanner;scanner",
        "--hidden-import=flask",
        "--hidden-import=flask_cors",
        "--hidden-import=psutil",
        "--hidden-import=webview",
        "--hidden-import=scanner",
        "--hidden-import=scanner.advanced_detector",
        "--hidden-import=scanner.cheat_detector_comprehensive",
        "--hidden-import=scanner.chrome_scanner_enhanced",
        "--hidden-import=scanner.process_scanner_improved",
        "--hidden-import=scanner.minecraft_scanner_optimized",
        "--noupx",
        "--clean",
        "app_main.py"
    ]
    
    print("\n[*] Building executable...")
    print("[*] This may take 2-5 minutes...\n")
    
    result = subprocess.run(cmd, capture_output=False, text=True)
    
    if result.returncode == 0:
        print("\n" + "=" * 70)
        print("  ✅ BUILD SUCCESSFUL!")
        print("=" * 70)
        print(f"  📦 Output: dist/SS-Tools-Native.exe")
        print(f"  🎨 GUI: Red-Dark Theme (Modern Design)")
        print(f"  🚀 Ready to run: Double-click the .exe file")
        print("=" * 70)
        
        # Cleanup
        if os.path.exists("app_main.py"):
            os.remove("app_main.py")
        
        return True
    else:
        print("\n❌ Build failed!")
        if os.path.exists("app_main.py"):
            os.remove("app_main.py")
        return False


if __name__ == "__main__":
    try:
        success = build_exe()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
