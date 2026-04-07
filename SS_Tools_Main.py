"""
SS Tools Scanner v3.0 - Complete Unified Desktop Application
6 Main Tabs with All Scanners Integrated
Pure Desktop GUI (No Web Browser Needed)
"""

import os
import sys
import json
import zipfile
import sqlite3
import platform
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import psutil
except ImportError:
    psutil = None

# Import all scanner modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from scanner.ghost_detector import scan_for_ghost_clients
    from scanner.cheat_detector_ultra_fast import scan_jar_ultra_fast
    from scanner.cheat_detector_comprehensive import scan_jar_ultra_fast as scan_comprehensive
    from scanner.minecraft_scanner_optimized import full_launcher_scan
    from scanner.chrome_scanner_enhanced import scan_chrome_history
    from scanner.process_scanner_improved import full_process_scan
    from scanner.deleted_files_advanced import DeletedFilesScanner
except:
    pass

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                    UNIFIED SCANNER ENGINE                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class UnifiedScanner:
    """All scanners integrated into one engine"""
    
    def __init__(self):
        self.deleted_scanner = DeletedFilesScanner()
    
    def scan_jar_complete(self, jar_path: str) -> dict:
        """Complete JAR scanning with all detection methods"""
        results = {
            'file': os.path.basename(jar_path),
            'ultra_fast': {},
            'comprehensive': {},
            'ghost_detection': {},
            'final_verdict': 'CLEAN',
            'confidence': 0
        }
        
        try:
            # Ultra-fast scanning
            results['ultra_fast'] = scan_jar_ultra_fast(jar_path)
            
            # Ghost client detection
            with zipfile.ZipFile(jar_path, 'r') as jar:
                class_files = [f for f in jar.namelist() if f.endswith('.class')]
            
            if class_files:
                results['ghost_detection'] = scan_for_ghost_clients(jar_path)
            
            # Determine final verdict
            if results['ghost_detection'].get('detected'):
                results['final_verdict'] = 'CRITICAL - Ghost Client'
                results['confidence'] = 95
            elif results['ultra_fast'].get('is_cheat'):
                risk = results['ultra_fast'].get('risk_level', 'MEDIUM')
                results['final_verdict'] = risk
                results['confidence'] = results['ultra_fast'].get('confidence', 50)
            else:
                results['confidence'] = 10
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def scan_minecraft_complete(self) -> dict:
        """Complete Minecraft scanning"""
        results = {
            'total_mods': 0,
            'cheats_detected': 0,
            'ghost_clients': 0,
            'files': [],
            'risk_summary': 'CLEAN'
        }
        
        try:
            launcher_results = full_launcher_scan()
            
            results['total_mods'] = launcher_results.get('total_mods', 0)
            results['cheats_detected'] = launcher_results.get('cheats_detected', 0)
            results['files'] = launcher_results.get('scans', [])[:20]
            
            if results['cheats_detected'] > 0:
                results['risk_summary'] = 'CRITICAL - CHEATS FOUND'
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def scan_system_complete(self) -> dict:
        """Complete system scanning (Browser + Processes + Deleted Files)"""
        results = {
            'browser': {},
            'processes': {},
            'deleted_files': {},
            'risk_level': 'CLEAN',
            'total_threats': 0
        }
        
        try:
            # Browser scan
            results['browser'] = scan_chrome_history()
            
            # Process scan
            if psutil:
                results['processes'] = full_process_scan()
                if results['processes'].get('malicious'):
                    results['total_threats'] += len(results['processes']['malicious'])
            
            # Deleted files scan
            results['deleted_files'] = self.deleted_scanner.scan_system()
            results['total_threats'] += results['deleted_files'].get('total_deleted', 0)
            
            # Determine risk level
            if results['total_threats'] > 0:
                results['risk_level'] = 'HIGH - THREATS DETECTED'
            elif results['browser'].get('risk_level') != 'CLEAN':
                results['risk_level'] = results['browser'].get('risk_level')
        
        except Exception as e:
            results['error'] = str(e)
        
        return results

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                        PyQt5 DESKTOP GUI (6 TABS)                        ║
# ╚══════════════════════════════════════════════════════════════════════════╝

try:
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QFont, QColor, QIcon, QPixmap
    HAS_PYQT5 = True
except ImportError:
    HAS_PYQT5 = False
    print("❌ PyQt5 not installed. Install with: pip install PyQt5")

if HAS_PYQT5:
    class ScannerWorker(QThread):
        finished = pyqtSignal(dict)
        
        def __init__(self, func):
            super().__init__()
            self.func = func
        
        def run(self):
            try:
                result = self.func()
                self.finished.emit(result)
            except Exception as e:
                self.finished.emit({'error': str(e)})
    
    class SSToolsGUI(QMainWindow):
        def __init__(self):
            super().__init__()
            self.scanner = UnifiedScanner()
            self.init_ui()
        
        def init_ui(self):
            self.setWindowTitle("SS Tools Scanner v3.0 - 6 In 1")
            self.setGeometry(50, 50, 1400, 900)
            self.apply_theme()
            
            widget = QWidget()
            self.setCentralWidget(widget)
            layout = QVBoxLayout(widget)
            
            # ═══ HEADER ═══
            header = QHBoxLayout()
            title = QLabel("🔍 SS Tools Scanner v3.0")
            title_font = QFont()
            title_font.setPointSize(18)
            title_font.setBold(True)
            title.setFont(title_font)
            title.setStyleSheet("color: #ff5252; margin: 10px;")
            header.addWidget(title)
            header.addStretch()
            
            status_label = QLabel("✓ Ready")
            status_label.setStyleSheet("color: #4caf50; font-weight: bold; margin: 10px;")
            self.status_label = status_label
            header.addWidget(status_label)
            
            layout.addLayout(header)
            
            # ═══ TABS (6 MAIN) ═══
            self.tabs = QTabWidget()
            self.tabs.setStyleSheet("""
                QTabBar::tab { 
                    background-color: #1a1a1a; 
                    color: #ffffff; 
                    padding: 12px 20px; 
                    margin: 2px;
                    border-radius: 4px;
                }
                QTabBar::tab:selected { 
                    background-color: #ff5252; 
                    color: white;
                }
                QTabBar::tab:hover {
                    background-color: #ff1744;
                }
            """)
            layout.addWidget(self.tabs)
            
            # Tab 1: Quick Scan (All Scanners)
            self.create_quick_scan_tab()
            
            # Tab 2: JAR Analysis
            self.create_jar_tab()
            
            # Tab 3: Minecraft
            self.create_minecraft_tab()
            
            # Tab 4: System (Browser + Processes + Deleted Files)
            self.create_system_tab()
            
            # Tab 5: Browser History
            self.create_browser_tab()
            
            # Tab 6: Advanced Tools
            self.create_advanced_tab()
        
        def apply_theme(self):
            """Apply red-dark professional theme"""
            self.setStyleSheet("""
                QMainWindow { background-color: #0a0a0a; }
                QWidget { background-color: #0a0a0a; color: #ffffff; }
                QLabel { color: #ffffff; }
                QPushButton { 
                    background-color: #ff5252; 
                    color: white; 
                    padding: 10px 20px; 
                    border-radius: 6px; 
                    font-weight: bold;
                    border: none;
                }
                QPushButton:hover { background-color: #ff1744; }
                QPushButton:pressed { background-color: #d50000; }
                QTextEdit { 
                    background-color: #1a1a1a; 
                    color: #00ff00;
                    border: 1px solid #ff5252;
                    font-family: Courier;
                    font-size: 11px;
                }
                QTabWidget { border: none; }
                QTabBar { background-color: #0a0a0a; }
                QProgressBar {
                    background-color: #1a1a1a;
                    border: 1px solid #ff5252;
                    border-radius: 4px;
                }
                QProgressBar::chunk { background-color: #ff5252; }
            """)
        
        def create_quick_scan_tab(self):
            """Tab 1: Quick Scan - All scanners in one"""
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # Buttons
            btn_layout = QHBoxLayout()
            
            scan_all_btn = QPushButton("⚡ SCAN ALL (Complete System)")
            scan_all_btn.clicked.connect(self.quick_scan_all)
            scan_all_btn.setMinimumHeight(40)
            
            scan_jar_btn = QPushButton("📦 Scan JAR")
            scan_jar_btn.clicked.connect(self.quick_scan_jar)
            scan_jar_btn.setMinimumHeight(40)
            
            btn_layout.addWidget(scan_all_btn)
            btn_layout.addWidget(scan_jar_btn)
            layout.addLayout(btn_layout)
            
            # Output
            self.quick_output = QTextEdit()
            self.quick_output.setReadOnly(True)
            self.quick_output.setText("🚀 Click a button to start scanning\n")
            layout.addWidget(self.quick_output)
            
            self.tabs.addTab(tab, "⚡ Quick Scan")
        
        def create_jar_tab(self):
            """Tab 2: JAR Analysis with Ghost Client Detection"""
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # File selector
            btn_layout = QHBoxLayout()
            select_btn = QPushButton("📂 Select JAR File")
            select_btn.clicked.connect(self.select_jar_file)
            scan_btn = QPushButton("🔍 Scan JAR")
            scan_btn.clicked.connect(self.scan_jar_complete)
            
            btn_layout.addWidget(select_btn)
            btn_layout.addWidget(scan_btn)
            layout.addLayout(btn_layout)
            
            # Filename label
            self.jar_label = QLabel("No file selected")
            self.jar_label.setStyleSheet("color: #4caf50;")
            layout.addWidget(self.jar_label)
            
            # Output
            self.jar_output = QTextEdit()
            self.jar_output.setReadOnly(True)
            self.jar_output.setText("Select a JAR file to scan\n")
            layout.addWidget(self.jar_output)
            
            self.tabs.addTab(tab, "📦 JAR Analysis")
        
        def create_minecraft_tab(self):
            """Tab 3: Minecraft Launcher Scanning"""
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            scan_btn = QPushButton("🎮 Scan All Minecraft Installations")
            scan_btn.clicked.connect(self.scan_minecraft)
            scan_btn.setMinimumHeight(40)
            layout.addWidget(scan_btn)
            
            self.mc_output = QTextEdit()
            self.mc_output.setReadOnly(True)
            self.mc_output.setText("Click to scan all Minecraft launchers\n")
            layout.addWidget(self.mc_output)
            
            self.tabs.addTab(tab, "🎮 Minecraft")
        
        def create_system_tab(self):
            """Tab 4: System Scan (Browser + Processes + Deleted Files)"""
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            scan_btn = QPushButton("⚙️ Full System Scan")
            scan_btn.clicked.connect(self.scan_system)
            scan_btn.setMinimumHeight(40)
            layout.addWidget(scan_btn)
            
            self.system_output = QTextEdit()
            self.system_output.setReadOnly(True)
            self.system_output.setText("Click to scan:\n  • Browser History\n  • Running Processes\n  • Deleted Files\n")
            layout.addWidget(self.system_output)
            
            self.tabs.addTab(tab, "⚙️ System Scan")
        
        def create_browser_tab(self):
            """Tab 5: Browser History Analysis"""
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            scan_btn = QPushButton("🌐 Scan Browser History")
            scan_btn.clicked.connect(self.scan_browser)
            scan_btn.setMinimumHeight(40)
            layout.addWidget(scan_btn)
            
            self.browser_output = QTextEdit()
            self.browser_output.setReadOnly(True)
            self.browser_output.setText("Click to scan:\n  • Chrome/Edge history\n  • Adult sites detection (80+)\n  • Suspicious URLs\n")
            layout.addWidget(self.browser_output)
            
            self.tabs.addTab(tab, "🌐 Browser")
        
        def create_advanced_tab(self):
            """Tab 6: Advanced Tools (Processes, Deleted Files, etc)"""
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # Buttons
            btn_layout = QHBoxLayout()
            
            proc_btn = QPushButton("⚙️ Scan Processes")
            proc_btn.clicked.connect(self.scan_processes)
            
            deleted_btn = QPushButton("🗑️ Scan Deleted Files")
            deleted_btn.clicked.connect(self.scan_deleted_files)
            
            btn_layout.addWidget(proc_btn)
            btn_layout.addWidget(deleted_btn)
            layout.addLayout(btn_layout)
            
            # Output
            self.advanced_output = QTextEdit()
            self.advanced_output.setReadOnly(True)
            self.advanced_output.setText("Click to:\n  • Detect malicious processes\n  • Find deleted files\n  • System security analysis\n")
            layout.addWidget(self.advanced_output)
            
            self.tabs.addTab(tab, "🔧 Advanced")
        
        # ═══ SCANNING METHODS ═══
        
        def quick_scan_all(self):
            self.quick_output.setText("🔄 Scanning JAR + System...\n")
            self.status_label.setText("🔄 Scanning...")
            
            # Quick scan JAR first
            if hasattr(self, 'selected_jar') and self.selected_jar:
                result = self.scanner.scan_jar_complete(self.selected_jar)
                self.quick_output.setText(self._format_jar_result(result))
            
            # Then system
            system_result = self.scanner.scan_system_complete()
            self.quick_output.append("\n" + self._format_system_result(system_result))
            
            self.status_label.setText("✓ Complete")
        
        def quick_scan_jar(self):
            if not hasattr(self, 'selected_jar'):
                self.quick_output.setText("❌ Please select a JAR file first (use JAR Analysis tab)")
                return
            
            self.quick_output.setText("🔄 Scanning JAR...\n")
            result = self.scanner.scan_jar_complete(self.selected_jar)
            self.quick_output.setText(self._format_jar_result(result))
        
        def select_jar_file(self):
            file, _ = QFileDialog.getOpenFileName(self, "Select JAR File", "", "JAR (*.jar)")
            if file:
                self.selected_jar = file
                self.jar_label.setText(f"✓ {os.path.basename(file)}")
        
        def scan_jar_complete(self):
            if not hasattr(self, 'selected_jar'):
                self.jar_output.setText("❌ Please select a JAR file first")
                return
            
            self.jar_output.setText("🔄 Analyzing JAR...\n")
            result = self.scanner.scan_jar_complete(self.selected_jar)
            self.jar_output.setText(self._format_jar_result(result))
        
        def scan_minecraft(self):
            self.mc_output.setText("🔄 Scanning Minecraft installations...\n")
            result = self.scanner.scan_minecraft_complete()
            
            output = "🎮 MINECRAFT SCAN RESULTS\n"
            output += "═" * 50 + "\n\n"
            output += f"📂 Total Mods: {result['total_mods']}\n"
            output += f"⚠️ Cheats Detected: {result['cheats_detected']}\n"
            output += f"🎯 Risk: {result['risk_summary']}\n\n"
            
            if result['files']:
                output += "🚨 Detected Files:\n"
                for f in result['files'][:10]:
                    output += f"  • {f.get('file', 'Unknown')}\n"
            
            self.mc_output.setText(output)
        
        def scan_system(self):
            self.system_output.setText("🔄 Full system scan running...\n")
            result = self.scanner.scan_system_complete()
            self.system_output.setText(self._format_system_result(result))
        
        def scan_browser(self):
            self.browser_output.setText("🔄 Scanning browser history...\n")
            result = scan_chrome_history() if 'scan_chrome_history' in dir() else {}
            
            output = "🌐 BROWSER HISTORY SCAN\n"
            output += "═" * 50 + "\n\n"
            output += f"👁️ Adult Sites: {result.get('adult', 0)}\n"
            output += f"⚠️ Suspicious Sites: {result.get('suspicious', 0)}\n"
            output += f"🎯 Risk: {result.get('risk_level', 'CLEAN')}\n"
            
            self.browser_output.setText(output)
        
        def scan_processes(self):
            self.advanced_output.setText("🔄 Scanning processes...\n")
            
            if psutil:
                result = full_process_scan() if 'full_process_scan' in dir() else {}
                output = "⚙️ PROCESS SCAN RESULTS\n"
                output += "═" * 50 + "\n\n"
                
                if result.get('malicious'):
                    output += f"🚨 Malicious Processes: {len(result['malicious'])}\n"
                    for proc in result['malicious'][:10]:
                        output += f"  ⚠️ {proc.get('name', 'Unknown')}\n"
                else:
                    output += "✅ No malicious processes detected\n"
                
                output += f"\n🎯 Risk: {result.get('risk_level', 'CLEAN')}\n"
            else:
                output = "❌ psutil not installed"
            
            self.advanced_output.setText(output)
        
        def scan_deleted_files(self):
            self.advanced_output.setText("🔄 Scanning for deleted files...\n")
            result = self.scanner.deleted_scanner.scan_system()
            
            output = "🗑️ DELETED FILES SCAN\n"
            output += "═" * 50 + "\n\n"
            output += f"📊 Deleted Candidates: {result.get('total_deleted', 0)}\n"
            output += f"🎯 Risk: {result.get('risk_level', 'CLEAN')}\n\n"
            
            if result.get('summary'):
                output += "📈 Summary:\n"
                for key, val in result['summary'].items():
                    output += f"  {key}: {val}\n"
            
            self.advanced_output.setText(output)
        
        def _format_jar_result(self, result: dict) -> str:
            output = "📦 JAR ANALYSIS COMPLETE\n"
            output += "═" * 50 + "\n\n"
            output += f"📄 File: {result.get('file', 'Unknown')}\n"
            output += f"🎯 Verdict: {result.get('final_verdict', 'CLEAN')}\n"
            output += f"📊 Confidence: {result.get('confidence', 0)}%\n\n"
            
            if result.get('ghost_detection', {}).get('detected'):
                output += "👻 GHOST CLIENTS DETECTED:\n"
                for ghost in result['ghost_detection'].get('ghosts', []):
                    output += f"  ⚠️ {ghost}\n"
            
            if result.get('ultra_fast', {}).get('detections'):
                output += "\n🚨 CHEAT DETECTIONS:\n"
                for det in result['ultra_fast'].get('detections', [])[:10]:
                    output += f"  • {det}\n"
            
            return output
        
        def _format_system_result(self, result: dict) -> str:
            output = "⚙️ FULL SYSTEM SCAN\n"
            output += "═" * 50 + "\n\n"
            output += f"🎯 Overall Risk: {result.get('risk_level', 'CLEAN')}\n"
            output += f"📊 Total Threats: {result.get('total_threats', 0)}\n\n"
            
            output += "🌐 BROWSER:\n"
            browser = result.get('browser', {})
            output += f"  Adult Sites: {browser.get('adult', 0)}\n"
            output += f"  Suspicious: {browser.get('suspicious', 0)}\n\n"
            
            output += "⚙️ PROCESSES:\n"
            processes = result.get('processes', {})
            output += f"  Malicious: {len(processes.get('malicious', []))}\n\n"
            
            output += "🗑️ DELETED FILES:\n"
            deleted = result.get('deleted_files', {})
            output += f"  Candidates: {deleted.get('total_deleted', 0)}\n"
            
            return output

    def run_gui():
        app = QApplication(sys.argv)
        window = SSToolsGUI()
        window.show()
        sys.exit(app.exec_())
else:
    def run_gui():
        print("❌ PyQt5 required!")

if __name__ == '__main__':
    if HAS_PYQT5:
        run_gui()
    else:
        print("Install PyQt5: pip install PyQt5")
