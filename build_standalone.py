"""
SS Tools Build Script - Create standalone .exe from unified scanner
No web dependencies - Pure PyQt5 desktop application
"""

import subprocess
import sys
import os

def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing dependencies...")
    
    packages = [
        'PyQt5==5.15.9',
        'PyInstaller==6.1.0',
        'psutil==5.9.5',
    ]
    
    for package in packages:
        print(f"  Installing {package}...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-q', package])
    
    print("✅ Dependencies installed!")

def build_exe():
    """Build standalone .exe using PyInstaller"""
    print("\n🔨 Building standalone .exe...")
    
    build_cmd = [
        sys.executable, '-m', 'PyInstaller',
        'SS_Tools_Scanner.py',
        '--onefile',
        '--windowed',
        '--name=SS_Tools_Scanner',
        '--icon=NONE',
        f'--distpath=./dist',
        f'--buildpath=./build',
        '--hidden-import=sqlite3',
        '--hidden-import=psutil',
        '-y'
    ]
    
    result = subprocess.run(build_cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("✅ Build successful!")
        print("\n📦 Output:")
        print(f"  Location: ./dist/SS_Tools_Scanner.exe")
        print(f"\n🚀 You can now run: SS_Tools_Scanner.exe")
    else:
        print("❌ Build failed!")
        print(result.stderr)
        sys.exit(1)

def cleanup():
    """Remove old files and keep only unified scanner"""
    print("\n🧹 Cleaning up old files...")
    
    old_files = [
        'app_ultra_fast.py',
        'app_enhanced.py',
        'app.py',
        'build_exe.py',
        'build.py'
    ]
    
    for file in old_files:
        if os.path.exists(file):
            os.remove(file)
            print(f"  Removed: {file}")
    
    # Keep only unified scanner and build script
    print("\n📂 Final structure:")
    print("  ✅ SS_Tools_Scanner.py (unified backend)")
    print("  ✅ build_standalone.py (this build script)")
    print("  ✅ requirements.txt")
    print("  ✅ templates/ (old - can be deleted)")
    print("  ✅ scanner/ (old modules - can be deleted)")

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║   SS Tools Standalone Builder v3.0                        ║
    ║   Create standalone .exe from unified scanner             ║
    ║   Pure PyQt5 Desktop • No Web Dependencies                ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    try:
        install_dependencies()
        build_exe()
        cleanup()
        
        print("\n" + "="*60)
        print("✅ BUILD COMPLETE!")
        print("="*60)
        print("\n🚀 Next steps:")
        print("  1. Find: ./dist/SS_Tools_Scanner.exe")
        print("  2. Run it directly - no dependencies needed!")
        print("  3. All scanning features available in desktop GUI")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
