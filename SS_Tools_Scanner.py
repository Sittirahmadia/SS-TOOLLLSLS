"""
SS Tools Scanner v3.0 - Unified Standalone Desktop Application
All-in-one cheat detection, ghost client detection, JAR inspection
No web browser needed - Pure PyQt5 GUI + all scanners integrated

Author: SS Tools
License: MIT
"""

import os
import sys
import json
import time
import re
import zipfile
import tempfile
import threading
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform

try:
    import psutil
except ImportError:
    psutil = None

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GLOBAL DETECTION SIGNATURES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

GHOST_PATTERNS = {
    'argon': {
        'keywords': ['argon', 'argonoclient', 'argon2k', 'argon_asm', 'com/argon', 'ArgonoModule'],
        'strings': ['Argon Client', 'argon.net', 'ArgonUtil'],
        'severity': 'CRITICAL'
    },
    'wurst_plus': {
        'keywords': ['wurstplus', 'wurst+', 'wurst_plus', 'WurstPlus', 'WurstPlusModule'],
        'strings': ['Wurst+', 'WurstPlus', 'Wurst Extended'],
        'severity': 'CRITICAL'
    },
    'instant_speed': {
        'keywords': ['instantspeed', 'instant_speed', 'speedhack', 'velocityfix', 'motionfix'],
        'strings': ['instant speed', 'velocity fix', 'motion hack'],
        'severity': 'CRITICAL'
    },
    'ghost_indicators': {
        'keywords': ['ghostclient', 'ghost_client', 'coilware', 'injector', 'hooking', 'bytecode', 'asm_'],
        'strings': ['ghost client', 'hidden client', 'stealth mode'],
        'severity': 'HIGH'
    }
}

CHEAT_SIGNATURES = {
    'combat': {
        'keywords': ['killaura', 'aura', 'aimbot', 'aimassist', 'autoclicker', 'cps', 'fastheal'],
        'strings': ['killaura', 'aimbot', 'auto attack'],
        'weight': 3
    },
    'movement': {
        'keywords': ['speed', 'flight', 'noclip', 'teleport', 'strafe', 'scaffold', 'nofall'],
        'strings': ['speed hack', 'flight', 'noclip'],
        'weight': 3
    },
    'vision': {
        'keywords': ['esp', 'xray', 'radar', 'tracers', 'wallhack', 'skeleton', 'glow'],
        'strings': ['esp', 'xray', 'wallhack'],
        'weight': 3
    },
    'builder': {
        'keywords': ['autobuild', 'builder', 'scaffold', 'structurebuild'],
        'strings': ['autobuild', 'scaffold'],
        'weight': 2
    },
    'macro': {
        'keywords': ['macro', 'bot', 'autoclick', 'autofarm', 'autorep'],
        'strings': ['macro', 'bot', 'autofarm'],
        'weight': 2
    },
    'injection': {
        'keywords': ['inject', 'hook', 'bytecode', 'asm', 'reflection', 'methodhandle'],
        'strings': ['injection', 'hook', 'bytecode'],
        'weight': 4
    },
    'cheat_client': {
        'keywords': ['phobos', 'impact', 'wurst', 'future', 'sigma', 'raven', 'huzuni', 'liquidbounce'],
        'strings': ['phobos', 'impact', 'wurst', 'future', 'sigma'],
        'weight': 5
    }
}

LEGITIMATE_MODS = {
    'optifine', 'sodium', 'iris', 'litematica', 'minihud', 'jei', 'emi',
    'fabric', 'forge', 'minecraft', 'rei', 'appleskin', 'waila', 'jade'
}

ADULT_KEYWORDS = [
    'porn', 'pornhub', 'xvideos', 'xxx', 'adult', 'sex', 'hentai', 'nude',
    'naked', 'redtube', 'youporn', 'xnxx', 'nhentai', 'bokep', 'bokepindo',
    'erome', 'xanimu', 'crazyshit', 'motherless'
]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DETECTION ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ScannerEngine:
    def __init__(self):
        self.compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        for category in CHEAT_SIGNATURES:
            self.compiled_patterns[category] = re.compile(
                '|'.join(CHEAT_SIGNATURES[category]['keywords']),
                re.IGNORECASE
            )
    
    def detect_ghost_clients(self, content: str) -> dict:
        """Fast ghost client detection"""
        ghosts = []
        confidence = 0
        content_lower = content.lower()
        
        for ghost_type, patterns in GHOST_PATTERNS.items():
            for keyword in patterns['keywords']:
                if keyword.lower() in content_lower:
                    ghosts.append(ghost_type)
                    confidence += 15
                    break
        
        return {
            'detected': len(ghosts) > 0,
            'ghosts': list(set(ghosts)),
            'confidence': min(100, confidence)
        }
    
    def detect_cheats(self, content: str) -> dict:
        """Ultra-fast cheat detection"""
        detections = []
        total_score = 0
        categories = set()
        content_lower = content.lower()
        
        for category, patterns in CHEAT_SIGNATURES.items():
            for keyword in patterns['keywords']:
                if keyword.lower() in content_lower:
                    detections.append({
                        'type': category,
                        'match': keyword,
                        'weight': patterns['weight']
                    })
                    categories.add(category)
                    total_score += patterns['weight']
                    break
        
        return {
            'detections': detections[:20],
            'categories': list(categories),
            'score': total_score,
            'is_cheat': total_score >= 5
        }
    
    def is_legitimate_mod(self, filename: str) -> bool:
        return any(mod in filename.lower() for mod in LEGITIMATE_MODS)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SCANNING FUNCTIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

detector = ScannerEngine()

def scan_jar_file(jar_path: str) -> dict:
    """Scan JAR file for cheats and ghost clients"""
    results = {
        'filename': os.path.basename(jar_path),
        'is_cheat': False,
        'confidence': 0,
        'detections': [],
        'categories': [],
        'ghost_clients': [],
        'files_scanned': 0,
        'risk_level': 'CLEAN',
        'error': None
    }
    
    try:
        with zipfile.ZipFile(jar_path, 'r') as jar:
            class_files = [f for f in jar.namelist() 
                          if f.endswith('.class') and not f.startswith('META-INF/')]
        
        if not class_files:
            return results
        
        results['files_scanned'] = len(class_files)
        total_score = 0
        all_detections = []
        ghost_found = False
        
        filename = os.path.basename(jar_path)
        if not detector.is_legitimate_mod(filename):
            with ThreadPoolExecutor(max_workers=16) as executor:
                futures = {}
                
                for class_file in class_files[:100]:
                    try:
                        with zipfile.ZipFile(jar_path, 'r') as jar:
                            content = jar.read(class_file)
                        
                        try:
                            text = content.decode('utf-8', errors='ignore')
                        except:
                            text = str(content)
                        
                        future = executor.submit(detector.detect_cheats, text)
                        futures[future] = class_file
                    except:
                        pass
                
                for future in as_completed(futures, timeout=2):
                    try:
                        result = future.result()
                        if result['is_cheat']:
                            all_detections.extend(result['detections'])
                            total_score += result['score']
                            results['categories'].extend(result['categories'])
                    except:
                        pass
        
        results['categories'] = list(set(results['categories']))
        
        if all_detections:
            results['is_cheat'] = True
            results['detections'] = all_detections[:15]
            results['confidence'] = min(100, total_score * 3)
            
            if 'cheat_client' in results['categories'] or 'injection' in results['categories']:
                results['risk_level'] = 'CRITICAL'
            elif results['confidence'] > 80:
                results['risk_level'] = 'HIGH'
            elif results['confidence'] > 50:
                results['risk_level'] = 'MEDIUM'
    
    except Exception as e:
        results['error'] = str(e)
    
    return results

def scan_minecraft_installations() -> dict:
    """Scan all Minecraft installations"""
    results = {
        'total_mods': 0,
        'cheats_detected': 0,
        'cheaty_files': [],
        'risk_summary': 'CLEAN'
    }
    
    try:
        launcher_paths = []
        home = os.path.expanduser('~')
        
        if platform.system() == 'Windows':
            launcher_paths = [
                os.path.join(home, '.minecraft/mods'),
                os.path.join(home, 'AppData/Local/MultiMC/instances'),
                os.path.join(home, '.prism-launcher/instances'),
            ]
        else:
            launcher_paths = [
                os.path.join(home, '.minecraft/mods'),
                os.path.join(home, '.config/MultiMC/instances'),
                os.path.join(home, '.config/PrismLauncher/instances'),
            ]
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {}
            
            for path in launcher_paths:
                if os.path.exists(path):
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            if file.endswith('.jar'):
                                full_path = os.path.join(root, file)
                                future = executor.submit(scan_jar_file, full_path)
                                futures[future] = full_path
                        
                        if len(futures) >= 100:
                            break
            
            for future in as_completed(futures, timeout=5):
                try:
                    jar_path = futures[future]
                    result = future.result()
                    
                    results['total_mods'] += 1
                    if result['is_cheat']:
                        results['cheats_detected'] += 1
                        results['cheaty_files'].append({
                            'name': result['filename'],
                            'risk': result['risk_level'],
                            'confidence': result['confidence']
                        })
                except:
                    pass
        
        if results['cheats_detected'] > 0:
            results['risk_summary'] = 'CRITICAL - CHEATS FOUND'
    
    except Exception as e:
        results['error'] = str(e)
    
    return results

def scan_browser_history() -> dict:
    """Scan browser history for suspicious content"""
    results = {
        'adult_sites': [],
        'suspicious_sites': [],
        'total_urls': 0,
        'risk_level': 'CLEAN'
    }
    
    try:
        import sqlite3
        
        home = os.path.expanduser('~')
        
        if platform.system() == 'Windows':
            chrome_history = os.path.join(home, 'AppData/Local/Google/Chrome/User Data/Default/History')
        else:
            chrome_history = os.path.join(home, '.config/google-chrome/Default/History')
        
        if os.path.exists(chrome_history):
            conn = sqlite3.connect(f'file:{chrome_history}?mode=ro', uri=True)
            cursor = conn.cursor()
            
            try:
                cursor.execute('SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT 500')
                urls = [row[0] for row in cursor.fetchall()]
                results['total_urls'] = len(urls)
                
                suspicious_keywords = ['cheat', 'hack', 'crack', 'bypass', 'injector']
                
                for url in urls:
                    url_lower = url.lower()
                    if any(kw in url_lower for kw in ADULT_KEYWORDS):
                        results['adult_sites'].append(url[:80])
                    elif any(kw in url_lower for kw in suspicious_keywords):
                        results['suspicious_sites'].append(url[:80])
                
                if results['adult_sites']:
                    results['risk_level'] = 'HIGH - ADULT CONTENT'
                elif results['suspicious_sites']:
                    results['risk_level'] = 'MEDIUM - SUSPICIOUS'
            finally:
                conn.close()
    
    except Exception as e:
        results['error'] = str(e)
    
    return results

def scan_processes() -> dict:
    """Scan running processes"""
    results = {
        'malicious': [],
        'risk_level': 'CLEAN'
    }
    
    if not psutil:
        return results
    
    try:
        malicious_keywords = ['cheatengine', 'autohotkey', 'ollydbg', 'x64dbg', 'ghidra', 'ida64']
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                if any(kw in name for kw in malicious_keywords):
                    results['malicious'].append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name']
                    })
            except:
                pass
        
        if results['malicious']:
            results['risk_level'] = 'CRITICAL - MALICIOUS PROCESSES'
    
    except Exception:
        pass
    
    return results

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DESKTOP GUI (PyQt5)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                                 QPushButton, QLabel, QTextEdit, QTabWidget, QWidget,
                                 QFileDialog, QProgressBar, QComboBox)
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QFont, QColor
    
    class ScannerThread(QThread):
        finished = pyqtSignal(dict)
        
        def __init__(self, scan_type):
            super().__init__()
            self.scan_type = scan_type
        
        def run(self):
            if self.scan_type == 'minecraft':
                result = scan_minecraft_installations()
            elif self.scan_type == 'browser':
                result = scan_browser_history()
            elif self.scan_type == 'processes':
                result = scan_processes()
            
            self.finished.emit(result)
    
    class SSToolsApp(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("SS Tools Scanner v3.0")
            self.setGeometry(100, 100, 1200, 800)
            self.init_ui()
        
        def init_ui(self):
            widget = QWidget()
            self.setCentralWidget(widget)
            layout = QVBoxLayout(widget)
            
            # Title
            title = QLabel("SS Tools Scanner - Unified Cheat Detection")
            title_font = QFont()
            title_font.setPointSize(16)
            title_font.setBold(True)
            title.setFont(title_font)
            title.setStyleSheet("color: #ff5252; padding: 10px;")
            layout.addWidget(title)
            
            # Tabs
            self.tabs = QTabWidget()
            layout.addWidget(self.tabs)
            
            # JAR Scan Tab
            jar_tab = QWidget()
            jar_layout = QVBoxLayout(jar_tab)
            
            jar_btn_layout = QHBoxLayout()
            self.jar_file_label = QLabel("No file selected")
            jar_btn = QPushButton("Select JAR File")
            jar_btn.clicked.connect(self.select_jar_file)
            self.scan_jar_btn = QPushButton("Scan JAR")
            self.scan_jar_btn.clicked.connect(self.scan_jar)
            
            jar_btn_layout.addWidget(jar_btn)
            jar_btn_layout.addWidget(self.scan_jar_btn)
            jar_layout.addLayout(jar_btn_layout)
            jar_layout.addWidget(self.jar_file_label)
            
            self.jar_output = QTextEdit()
            self.jar_output.setReadOnly(True)
            jar_layout.addWidget(self.jar_output)
            self.tabs.addTab(jar_tab, "JAR Scanner")
            
            # Minecraft Tab
            mc_tab = QWidget()
            mc_layout = QVBoxLayout(mc_tab)
            self.scan_mc_btn = QPushButton("Scan Minecraft Installations")
            self.scan_mc_btn.clicked.connect(self.scan_minecraft)
            mc_layout.addWidget(self.scan_mc_btn)
            self.mc_output = QTextEdit()
            self.mc_output.setReadOnly(True)
            mc_layout.addWidget(self.mc_output)
            self.tabs.addTab(mc_tab, "Minecraft")
            
            # Browser Tab
            browser_tab = QWidget()
            browser_layout = QVBoxLayout(browser_tab)
            self.scan_browser_btn = QPushButton("Scan Browser History")
            self.scan_browser_btn.clicked.connect(self.scan_browser)
            browser_layout.addWidget(self.scan_browser_btn)
            self.browser_output = QTextEdit()
            self.browser_output.setReadOnly(True)
            browser_layout.addWidget(self.browser_output)
            self.tabs.addTab(browser_tab, "Browser")
            
            # Processes Tab
            proc_tab = QWidget()
            proc_layout = QVBoxLayout(proc_tab)
            self.scan_proc_btn = QPushButton("Scan Processes")
            self.scan_proc_btn.clicked.connect(self.scan_processes)
            proc_layout.addWidget(self.scan_proc_btn)
            self.proc_output = QTextEdit()
            self.proc_output.setReadOnly(True)
            proc_layout.addWidget(self.proc_output)
            self.tabs.addTab(proc_tab, "Processes")
            
            # Progress bar
            self.progress = QProgressBar()
            self.progress.setVisible(False)
            layout.addWidget(self.progress)
            
            # Status
            self.status_label = QLabel("Ready")
            self.status_label.setStyleSheet("color: #4caf50; font-weight: bold;")
            layout.addWidget(self.status_label)
            
            self.selected_jar = None
        
        def select_jar_file(self):
            file, _ = QFileDialog.getOpenFileName(self, "Select JAR File", "", "JAR Files (*.jar)")
            if file:
                self.selected_jar = file
                self.jar_file_label.setText(f"Selected: {os.path.basename(file)}")
        
        def scan_jar(self):
            if not self.selected_jar:
                self.jar_output.setText("⚠️ Please select a JAR file first!")
                return
            
            self.jar_output.setText("🔍 Scanning...\n")
            result = scan_jar_file(self.selected_jar)
            
            output = f"File: {result['filename']}\n"
            output += f"Risk Level: {result['risk_level']}\n"
            output += f"Confidence: {result['confidence']}%\n"
            output += f"Files Scanned: {result['files_scanned']}\n"
            output += f"Categories: {', '.join(result['categories']) if result['categories'] else 'None'}\n\n"
            
            if result['detections']:
                output += "Detections:\n"
                for det in result['detections']:
                    output += f"  - {det['type']}: {det['match']} (weight: {det['weight']})\n"
            else:
                output += "No threats detected ✅\n"
            
            self.jar_output.setText(output)
        
        def scan_minecraft(self):
            self.scan_mc_btn.setEnabled(False)
            self.status_label.setText("🔄 Scanning Minecraft installations...")
            
            thread = ScannerThread('minecraft')
            thread.finished.connect(self.on_minecraft_scan_finished)
            thread.start()
        
        def on_minecraft_scan_finished(self, result):
            output = f"Total Mods Found: {result['total_mods']}\n"
            output += f"Cheats Detected: {result['cheats_detected']}\n"
            output += f"Risk Summary: {result['risk_summary']}\n\n"
            
            if result['cheaty_files']:
                output += "Cheaty Files:\n"
                for f in result['cheaty_files']:
                    output += f"  - {f['name']} ({f['risk']}, {f['confidence']}%)\n"
            
            self.mc_output.setText(output)
            self.scan_mc_btn.setEnabled(True)
            self.status_label.setText("✅ Scan complete")
        
        def scan_browser(self):
            self.scan_browser_btn.setEnabled(False)
            self.status_label.setText("🔄 Scanning browser history...")
            
            thread = ScannerThread('browser')
            thread.finished.connect(self.on_browser_scan_finished)
            thread.start()
        
        def on_browser_scan_finished(self, result):
            output = f"Total URLs Scanned: {result['total_urls']}\n"
            output += f"Risk Level: {result['risk_level']}\n\n"
            
            if result['adult_sites']:
                output += f"Adult Sites Found: {len(result['adult_sites'])}\n"
            
            if result['suspicious_sites']:
                output += f"Suspicious Sites: {len(result['suspicious_sites'])}\n"
            
            self.browser_output.setText(output)
            self.scan_browser_btn.setEnabled(True)
            self.status_label.setText("✅ Scan complete")
        
        def scan_processes(self):
            self.scan_proc_btn.setEnabled(False)
            self.status_label.setText("🔄 Scanning processes...")
            
            result = scan_processes()
            
            output = f"Risk Level: {result['risk_level']}\n"
            if result['malicious']:
                output += f"Malicious Processes: {len(result['malicious'])}\n"
                for proc in result['malicious']:
                    output += f"  - {proc['name']} (PID: {proc['pid']})\n"
            else:
                output += "No malicious processes found ✅\n"
            
            self.proc_output.setText(output)
            self.scan_proc_btn.setEnabled(True)
            self.status_label.setText("✅ Scan complete")
    
    def run_gui():
        app = QApplication(sys.argv)
        window = SSToolsApp()
        window.show()
        sys.exit(app.exec_())

except ImportError:
    print("❌ PyQt5 not installed. Install with: pip install PyQt5")
    print("Using fallback CLI mode instead.\n")
    
    def run_gui():
        print("SS Tools Scanner - CLI Mode")
        print("=" * 50)
        
        while True:
            print("\n1. Scan JAR File")
            print("2. Scan Minecraft Installations")
            print("3. Scan Browser History")
            print("4. Scan Processes")
            print("5. Exit")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                jar_path = input("Enter JAR file path: ").strip()
                if os.path.exists(jar_path):
                    result = scan_jar_file(jar_path)
                    print(json.dumps(result, indent=2))
            
            elif choice == '2':
                result = scan_minecraft_installations()
                print(json.dumps(result, indent=2))
            
            elif choice == '3':
                result = scan_browser_history()
                print(json.dumps(result, indent=2))
            
            elif choice == '4':
                result = scan_processes()
                print(json.dumps(result, indent=2))
            
            elif choice == '5':
                break

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN ENTRY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║   SS Tools Scanner v3.0 - Unified Cheat Detection        ║
    ║   All-in-one JAR, Minecraft, Browser & Process Scanner   ║
    ║   No Web Browser • Pure Desktop Application              ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    run_gui()
