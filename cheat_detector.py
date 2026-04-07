"""
SS Tools - Complete Cheat Detection Scanner v3.0
Pure Desktop Application - NO WEB BROWSER NEEDED
All scanners integrated into single executable file
"""

import os
import sys
import json
import re
import zipfile
import sqlite3
import tempfile
import platform
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import psutil
except ImportError:
    psutil = None

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                    DETECTION PATTERNS DATABASE                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class CheatPatterns:
    """All detection patterns in one class"""
    
    GHOST_CLIENTS = {
        'argon': ['argon', 'argonoclient', 'argon2k', 'ArgonoModule'],
        'wurst_plus': ['wurstplus', 'wurst+', 'WurstPlus', 'WurstPlusModule'],
        'instant_speed': ['instantspeed', 'instant_speed', 'speedhack', 'velocityfix'],
        'hypixel_bypass': ['hypixelbypass', 'antiflyhack', 'flagbypass']
    }
    
    CHEATS = {
        'combat': ['killaura', 'aura', 'aimbot', 'autoclicker', 'fastheal', 'velocity'],
        'movement': ['speed', 'flight', 'noclip', 'teleport', 'strafe', 'scaffold', 'nofall'],
        'vision': ['esp', 'xray', 'radar', 'wallhack', 'skeleton', 'tracers', 'glow'],
        'builder': ['autobuild', 'builder', 'structurebuild', 'fastbuild'],
        'macro': ['macro', 'bot', 'autoclick', 'autofarm', 'autorep', 'autofish', 'autominer'],
        'injection': ['inject', 'hook', 'bytecode', 'asm', 'reflection', 'methodhandle'],
        'known_client': ['phobos', 'impact', 'wurst', 'future', 'sigma', 'raven', 'huzuni', 'liquidbounce']
    }
    
    LEGITIMATE_MODS = {'optifine', 'sodium', 'iris', 'jei', 'emi', 'fabric', 'forge', 'minecraft'}
    
    ADULT_SITES = {'porn', 'pornhub', 'xvideos', 'xxx', 'hentai', 'nhentai', 'bokep', 'xanimu'}
    
    MALICIOUS_PROCS = ['cheatengine', 'autohotkey', 'ollydbg', 'x64dbg', 'ghidra', 'ida64', 'frida']

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                       SCANNER ENGINE (CORE)                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class Scanner:
    """Complete scanner engine"""
    
    def __init__(self):
        self.patterns = CheatPatterns()
    
    def scan_jar(self, jar_path: str) -> dict:
        """Scan JAR file for cheats and ghost clients"""
        result = {
            'file': os.path.basename(jar_path),
            'is_cheat': False,
            'risk': 'CLEAN',
            'confidence': 0,
            'detections': [],
            'categories': []
        }
        
        try:
            with zipfile.ZipFile(jar_path, 'r') as jar:
                classes = [f for f in jar.namelist() if f.endswith('.class')]
            
            if not classes:
                return result
            
            # Skip legitimate mods
            if any(mod in os.path.basename(jar_path).lower() for mod in self.patterns.LEGITIMATE_MODS):
                return result
            
            detections = []
            content_cache = {}
            
            with ThreadPoolExecutor(max_workers=16) as executor:
                futures = {}
                for cls in classes[:100]:
                    try:
                        with zipfile.ZipFile(jar_path, 'r') as jar:
                            content = jar.read(cls).decode('utf-8', errors='ignore')
                        future = executor.submit(self._check_content, content)
                        futures[future] = cls
                    except:
                        pass
                
                for future in as_completed(futures, timeout=2):
                    try:
                        det = future.result()
                        if det:
                            detections.extend(det)
                    except:
                        pass
            
            if detections:
                result['is_cheat'] = True
                result['detections'] = list(set(detections))[:15]
                result['categories'] = list(set([d.split(':')[0] for d in detections]))
                result['confidence'] = min(100, len(result['detections']) * 8)
                
                if result['confidence'] > 70:
                    result['risk'] = 'CRITICAL'
                elif result['confidence'] > 40:
                    result['risk'] = 'HIGH'
                else:
                    result['risk'] = 'MEDIUM'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _check_content(self, content: str) -> list:
        """Check content for cheat patterns"""
        findings = []
        content_lower = content.lower()
        
        # Check ghost clients
        for ghost_type, keywords in self.patterns.GHOST_CLIENTS.items():
            for kw in keywords:
                if kw.lower() in content_lower:
                    findings.append(f'ghost:{ghost_type}')
                    break
        
        # Check cheats
        for category, keywords in self.patterns.CHEATS.items():
            for kw in keywords:
                if kw.lower() in content_lower:
                    findings.append(f'{category}:{kw}')
                    break
        
        return list(set(findings))
    
    def scan_minecraft(self) -> dict:
        """Scan Minecraft installations"""
        result = {'total': 0, 'cheats': 0, 'files': [], 'risk': 'CLEAN'}
        
        try:
            paths = []
            home = os.path.expanduser('~')
            
            if platform.system() == 'Windows':
                paths = [f"{home}\\.minecraft\\mods", f"{home}\\AppData\\Local\\MultiMC\\instances"]
            else:
                paths = [f"{home}/.minecraft/mods", f"{home}/.config/MultiMC/instances"]
            
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = {}
                for path in paths:
                    if os.path.exists(path):
                        for root, dirs, files in os.walk(path):
                            for file in files:
                                if file.endswith('.jar'):
                                    full_path = os.path.join(root, file)
                                    future = executor.submit(self.scan_jar, full_path)
                                    futures[future] = full_path
                            if len(futures) >= 100:
                                break
                
                for future in as_completed(futures, timeout=5):
                    try:
                        scan_result = future.result()
                        result['total'] += 1
                        if scan_result['is_cheat']:
                            result['cheats'] += 1
                            result['files'].append(scan_result['file'])
                    except:
                        pass
            
            if result['cheats'] > 0:
                result['risk'] = 'CRITICAL - CHEATS FOUND'
        except:
            pass
        
        return result
    
    def scan_browser(self) -> dict:
        """Scan browser history"""
        result = {'adult': 0, 'suspicious': 0, 'risk': 'CLEAN'}
        
        try:
            home = os.path.expanduser('~')
            if platform.system() == 'Windows':
                history = f"{home}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
            else:
                history = f"{home}/.config/google-chrome/Default/History"
            
            if os.path.exists(history):
                conn = sqlite3.connect(f'file:{history}?mode=ro', uri=True)
                cursor = conn.cursor()
                cursor.execute('SELECT url FROM urls LIMIT 500')
                
                for row in cursor.fetchall():
                    url = row[0].lower()
                    if any(site in url for site in self.patterns.ADULT_SITES):
                        result['adult'] += 1
                    elif any(word in url for word in ['hack', 'cheat', 'crack', 'bypass']):
                        result['suspicious'] += 1
                
                conn.close()
                
                if result['adult'] > 0:
                    result['risk'] = 'HIGH - ADULT CONTENT'
                elif result['suspicious'] > 0:
                    result['risk'] = 'MEDIUM - SUSPICIOUS'
        except:
            pass
        
        return result
    
    def scan_processes(self) -> dict:
        """Scan running processes"""
        result = {'malicious': [], 'risk': 'CLEAN'}
        
        if psutil:
            try:
                for proc in psutil.process_iter(['name']):
                    if any(mal in proc.info['name'].lower() for mal in self.patterns.MALICIOUS_PROCS):
                        result['malicious'].append(proc.info['name'])
                
                if result['malicious']:
                    result['risk'] = 'CRITICAL - MALICIOUS PROCESSES'
            except:
                pass
        
        return result

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                     PyQt5 DESKTOP GUI                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

try:
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QFont, QColor
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False

if HAS_PYQT5:
    class WorkerThread(QThread):
        finished = pyqtSignal(dict)
        def __init__(self, func):
            super().__init__()
            self.func = func
        def run(self):
            self.finished.emit(self.func())
    
    class SSToolsApp(QMainWindow):
        def __init__(self):
            super().__init__()
            self.scanner = Scanner()
            self.init_ui()
        
        def init_ui(self):
            self.setWindowTitle("SS Tools Scanner v3.0")
            self.setGeometry(100, 100, 1100, 750)
            self.setStyleSheet("""
                QMainWindow { background-color: #0a0a0a; }
                QLabel { color: #ffffff; }
                QPushButton { background-color: #ff5252; color: white; padding: 8px; border-radius: 4px; font-weight: bold; }
                QPushButton:hover { background-color: #ff1744; }
                QTextEdit { background-color: #1a1a1a; color: #ffffff; border: 1px solid #ff5252; }
            """)
            
            widget = QWidget()
            self.setCentralWidget(widget)
            layout = QVBoxLayout(widget)
            
            # Title
            title = QLabel("SS Tools Scanner v3.0 - Pure Desktop Application")
            title_font = QFont()
            title_font.setPointSize(14)
            title_font.setBold(True)
            title.setFont(title_font)
            title.setStyleSheet("color: #ff5252; padding: 15px;")
            layout.addWidget(title)
            
            # Tabs
            self.tabs = QTabWidget()
            self.tabs.setStyleSheet("QTabWidget { color: #ffffff; } QTabBar::tab { background-color: #1a1a1a; color: #ffffff; padding: 8px; }")
            layout.addWidget(self.tabs)
            
            # ─── JAR Tab ───
            jar_widget = QWidget()
            jar_layout = QVBoxLayout(jar_widget)
            jar_btn = QPushButton("📦 Select & Scan JAR File")
            jar_btn.clicked.connect(self.scan_jar_dialog)
            self.jar_output = QTextEdit()
            self.jar_output.setReadOnly(True)
            jar_layout.addWidget(jar_btn)
            jar_layout.addWidget(self.jar_output)
            self.tabs.addTab(jar_widget, "JAR Scanner")
            
            # ─── Minecraft Tab ───
            mc_widget = QWidget()
            mc_layout = QVBoxLayout(mc_widget)
            mc_btn = QPushButton("🎮 Scan Minecraft Installations")
            mc_btn.clicked.connect(self.scan_minecraft_threaded)
            self.mc_output = QTextEdit()
            self.mc_output.setReadOnly(True)
            mc_layout.addWidget(mc_btn)
            mc_layout.addWidget(self.mc_output)
            self.tabs.addTab(mc_widget, "Minecraft")
            
            # ─── Browser Tab ───
            browser_widget = QWidget()
            browser_layout = QVBoxLayout(browser_widget)
            browser_btn = QPushButton("🌐 Scan Browser History")
            browser_btn.clicked.connect(self.scan_browser_threaded)
            self.browser_output = QTextEdit()
            self.browser_output.setReadOnly(True)
            browser_layout.addWidget(browser_btn)
            browser_layout.addWidget(self.browser_output)
            self.tabs.addTab(browser_widget, "Browser")
            
            # ─── Processes Tab ───
            proc_widget = QWidget()
            proc_layout = QVBoxLayout(proc_widget)
            proc_btn = QPushButton("⚙️ Scan Running Processes")
            proc_btn.clicked.connect(self.scan_processes_threaded)
            self.proc_output = QTextEdit()
            self.proc_output.setReadOnly(True)
            proc_layout.addWidget(proc_btn)
            proc_layout.addWidget(self.proc_output)
            self.tabs.addTab(proc_widget, "Processes")
            
            # Status
            self.status = QLabel("✓ Ready")
            self.status.setStyleSheet("color: #4caf50; font-weight: bold; padding: 10px;")
            layout.addWidget(self.status)
        
        def scan_jar_dialog(self):
            file, _ = QFileDialog.getOpenFileName(self, "Select JAR File", "", "JAR (*.jar)")
            if file:
                self.jar_output.setText("🔍 Scanning...")
                result = self.scanner.scan_jar(file)
                self.display_jar_result(result)
        
        def display_jar_result(self, result):
            text = f"📄 File: {result['file']}\n"
            text += f"🎯 Risk Level: {result['risk']}\n"
            text += f"📊 Confidence: {result['confidence']}%\n"
            text += f"🏷️ Categories: {', '.join(result['categories']) if result['categories'] else 'None'}\n\n"
            if result['detections']:
                text += "🚨 Detections:\n"
                for d in result['detections']:
                    text += f"  • {d}\n"
            else:
                text += "✅ No threats detected\n"
            self.jar_output.setText(text)
        
        def scan_minecraft_threaded(self):
            thread = WorkerThread(self.scanner.scan_minecraft)
            thread.finished.connect(self.display_minecraft_result)
            thread.start()
            self.status.setText("🔄 Scanning Minecraft...")
        
        def display_minecraft_result(self, result):
            text = f"📂 Total Mods: {result['total']}\n"
            text += f"⚠️ Cheats Found: {result['cheats']}\n"
            text += f"🎯 Risk Level: {result['risk']}\n"
            if result['files']:
                text += f"\n🚨 Cheaty Files:\n"
                for f in result['files']:
                    text += f"  • {f}\n"
            else:
                text += f"\n✅ All mods are clean\n"
            self.mc_output.setText(text)
            self.status.setText("✓ Scan complete")
        
        def scan_browser_threaded(self):
            thread = WorkerThread(self.scanner.scan_browser)
            thread.finished.connect(self.display_browser_result)
            thread.start()
            self.status.setText("🔄 Scanning browser history...")
        
        def display_browser_result(self, result):
            text = f"👁️ Adult Sites: {result['adult']}\n"
            text += f"⚠️ Suspicious Sites: {result['suspicious']}\n"
            text += f"🎯 Risk Level: {result['risk']}\n"
            self.browser_output.setText(text)
            self.status.setText("✓ Scan complete")
        
        def scan_processes_threaded(self):
            thread = WorkerThread(self.scanner.scan_processes)
            thread.finished.connect(self.display_processes_result)
            thread.start()
            self.status.setText("🔄 Scanning processes...")
        
        def display_processes_result(self, result):
            if result['malicious']:
                text = f"🚨 Malicious Processes Found:\n"
                for p in result['malicious']:
                    text += f"  ⚠️ {p}\n"
            else:
                text = f"✅ No malicious processes detected\n"
            text += f"\n🎯 Risk Level: {result['risk']}\n"
            self.proc_output.setText(text)
            self.status.setText("✓ Scan complete")

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                       MAIN EXECUTION                                     ║
# ╚══════════════════════════════════════════════════════════════════════════╝

if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════════════════════╗
║            SS Tools Scanner v3.0 - Pure Desktop Application             ║
║     All-in-One Cheat Detection • No Web Browser • No Dependencies       ║
╚══════════════════════════════════════════════════════════════════════════╝
    """)
    
    if HAS_PYQT5:
        app = QApplication(sys.argv)
        window = SSToolsApp()
        window.show()
        sys.exit(app.exec_())
    else:
        print("❌ PyQt5 not installed!")
        print("Install with: pip install PyQt5 psutil")
        print("\nFallback CLI mode:\n")
        
        scanner = Scanner()
        
        while True:
            print("\n1️⃣  Scan JAR File")
            print("2️⃣  Scan Minecraft")
            print("3️⃣  Scan Browser History")
            print("4️⃣  Scan Processes")
            print("5️⃣  Exit")
            
            choice = input("\n➤ Choice: ").strip()
            
            if choice == '1':
                path = input("JAR path: ").strip()
                if os.path.exists(path):
                    print(json.dumps(scanner.scan_jar(path), indent=2))
            elif choice == '2':
                print(json.dumps(scanner.scan_minecraft(), indent=2))
            elif choice == '3':
                print(json.dumps(scanner.scan_browser(), indent=2))
            elif choice == '4':
                print(json.dumps(scanner.scan_processes(), indent=2))
            elif choice == '5':
                break
