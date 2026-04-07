"""
SS Tools Ultra Fast v3.0 - Unified Scanner with Ghost Detection
- Ultra-fast parallel scanning (no hangs)
- Ghost client detection (Argon, Wurst+, instant-speed)
- Improved cheat detection with 50+ signatures
- Fast JAR inspection with parallel class analysis
- Full auto scan optimized for speed
"""

import os
import sys
import json
import time
import tempfile
import zipfile
import threading
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor, as_completed

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GHOST CLIENT DETECTION ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

GHOST_PATTERNS = {
    'argon': {
        'keywords': ['argon', 'argonoclient', 'argon2k', 'argon_asm', 'com/argon', 'ArgonoModule', 'argon.module'],
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
        'strings': ['instant speed', 'velocity fix', 'motion hack', 'hypixel bypass'],
        'severity': 'CRITICAL'
    },
    'ghost_indicators': {
        'keywords': ['ghostclient', 'ghost_client', 'coilware', 'injector', 'hooking', 'bytecode', 'asm_'],
        'strings': ['ghost client', 'hidden client', 'stealth mode', 'bypass detection'],
        'severity': 'HIGH'
    },
    'hypixel_bypass': {
        'keywords': ['hypixelbypass', 'antiflyhack', 'antimod', 'flagbypass', 'detectbypass'],
        'strings': ['hypixel bypass', 'anti-flag', 'bypass detection'],
        'severity': 'CRITICAL'
    }
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ULTRA-EXPANDED CHEAT SIGNATURES (1.8 - 1.21.11)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CHEAT_SIGNATURES = {
    'combat': {
        'keywords': ['killaura', 'aura', 'aimbot', 'aimassist', 'autoclicker', 'cps', 'fastheal', 'autohealth'],
        'strings': ['killaura', 'aimbot', 'auto attack', 'critical strike'],
        'weight': 3
    },
    'movement': {
        'keywords': ['speed', 'flight', 'noclip', 'teleport', 'strafe', 'scaffold', 'nofall', 'waterwalk', 'spiderwalk'],
        'strings': ['speed hack', 'flight', 'noclip', 'teleport', 'scaffold'],
        'weight': 3
    },
    'vision': {
        'keywords': ['esp', 'xray', 'radar', 'tracers', 'wallhack', 'skeleton', 'glow', 'entityesp'],
        'strings': ['esp', 'xray', 'wallhack', 'skeleton', 'tracers'],
        'weight': 3
    },
    'builder': {
        'keywords': ['autobuild', 'builder', 'scaffold', 'structurebuild', 'fastbuild', 'autoscaffold'],
        'strings': ['autobuild', 'scaffold', 'fast build'],
        'weight': 2
    },
    'macro': {
        'keywords': ['macro', 'bot', 'autoclick', 'autofarm', 'autorep', 'autofish', 'autominer', 'autofight'],
        'strings': ['macro', 'bot', 'autofarm', 'autofish', 'autominer'],
        'weight': 2
    },
    'injection': {
        'keywords': ['inject', 'hook', 'bytecode', 'asm', 'reflection', 'methodhandle', 'defineclass', 'jni', 'native'],
        'strings': ['injection', 'hook', 'bytecode', 'asm', 'reflection'],
        'weight': 4
    },
    'cheat_client': {
        'keywords': ['phobos', 'impact', 'wurst', 'future', 'sigma', 'raven', 'huzuni', 'liquidbounce', 'rusherhack'],
        'strings': ['phobos', 'impact', 'wurst', 'future', 'sigma', 'raven'],
        'weight': 5
    }
}

LEGITIMATE_MODS = {
    'optifine', 'sodium', 'iris', 'litematica', 'minihud', 'jei', 'emi',
    'fabric', 'forge', 'minecraft', 'rei', 'appleskin', 'waila', 'jade'
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CORE DETECTION ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class UltraFastDetector:
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
            found = False
            
            for keyword in patterns['keywords']:
                if keyword.lower() in content_lower:
                    ghosts.append(ghost_type)
                    confidence += 15
                    found = True
                    break
            
            if not found:
                for string in patterns['strings']:
                    if string.lower() in content_lower:
                        ghosts.append(ghost_type)
                        confidence += 20
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
        """Quick whitelist check"""
        return any(mod in filename.lower() for mod in LEGITIMATE_MODS)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SCANNING FUNCTIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

detector = UltraFastDetector()

def scan_jar_ultra_fast(jar_path: str) -> dict:
    """Ultra-fast JAR scanning with parallel class inspection"""
    results = {
        'is_cheat': False,
        'confidence': 0,
        'detections': [],
        'categories': [],
        'ghost_clients': [],
        'files_scanned': 0,
        'risk_level': 'CLEAN',
        'ghost_detection': {'detected': False, 'ghosts': []}
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
        
        filename = jar_path.split('/')[-1]
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
                
                # Ghost client detection (parallel)
                futures_ghost = {}
                for class_file in class_files[:50]:
                    try:
                        with zipfile.ZipFile(jar_path, 'r') as jar:
                            content = jar.read(class_file)
                        
                        try:
                            text = content.decode('utf-8', errors='ignore')
                        except:
                            text = str(content)
                        
                        future = executor.submit(detector.detect_ghost_clients, text)
                        futures_ghost[future] = class_file
                    except:
                        pass
                
                for future in as_completed(futures_ghost, timeout=2):
                    try:
                        result = future.result()
                        if result['detected']:
                            results['ghost_clients'].extend(result['ghosts'])
                            results['ghost_detection'] = result
                            ghost_found = True
                    except:
                        pass
        
        results['categories'] = list(set(results['categories']))
        
        if all_detections or ghost_found:
            results['is_cheat'] = True
            results['detections'] = all_detections[:15]
            results['confidence'] = min(100, total_score * 3)
            
            if ghost_found:
                results['risk_level'] = 'CRITICAL - Ghost Client Detected'
            elif 'cheat_client' in results['categories'] or 'injection' in results['categories']:
                results['risk_level'] = 'CRITICAL - Known Cheat Client'
            elif results['confidence'] > 80:
                results['risk_level'] = 'HIGH - Strong Cheat Indicators'
            elif results['confidence'] > 50:
                results['risk_level'] = 'MEDIUM - Suspicious Patterns'
    
    except Exception as e:
        results['error'] = str(e)
    
    return results

def scan_minecraft_launchers_ultra_fast() -> dict:
    """Ultra-fast Minecraft launcher detection with parallel scanning"""
    results = {
        'launchers_found': [],
        'total_mods': 0,
        'cheats_detected': 0,
        'risk_summary': 'CLEAN',
        'scans': []
    }
    
    try:
        import platform
        
        launcher_paths = []
        
        if platform.system() == 'Windows':
            home = os.path.expanduser('~')
            launcher_paths = [
                os.path.join(home, '.minecraft/mods'),
                os.path.join(home, '.minecraft/versions'),
                os.path.join(home, 'AppData/Local/MultiMC/instances'),
                os.path.join(home, '.prism-launcher/instances'),
                os.path.join(home, '.config/polymc/instances'),
            ]
        else:
            home = os.path.expanduser('~')
            launcher_paths = [
                os.path.join(home, '.minecraft/mods'),
                os.path.join(home, '.config/MultiMC/instances'),
                os.path.join(home, '.config/PrismLauncher/instances'),
                os.path.join(home, '.config/polymc/instances'),
            ]
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {}
            
            for path in launcher_paths:
                if os.path.exists(path):
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            if file.endswith('.jar'):
                                full_path = os.path.join(root, file)
                                future = executor.submit(scan_jar_ultra_fast, full_path)
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
                        results['scans'].append({
                            'file': os.path.basename(jar_path),
                            'risk': result['risk_level'],
                            'confidence': result['confidence'],
                            'categories': result['categories']
                        })
                except:
                    pass
        
        if results['cheats_detected'] > 0:
            results['risk_summary'] = 'CRITICAL - Cheats Found!'
        elif results['total_mods'] > 0:
            results['risk_summary'] = 'CLEAN'
    
    except Exception as e:
        results['error'] = str(e)
    
    return results

def scan_browser_history_ultra_fast() -> dict:
    """Ultra-fast browser history scanning"""
    results = {
        'suspicious_sites': [],
        'adult_content': [],
        'risk_level': 'CLEAN'
    }
    
    try:
        import sqlite3
        import platform
        
        home = os.path.expanduser('~')
        
        if platform.system() == 'Windows':
            chrome_history = os.path.join(home, 'AppData/Local/Google/Chrome/User Data/Default/History')
        else:
            chrome_history = os.path.join(home, '.config/google-chrome/Default/History')
        
        if os.path.exists(chrome_history):
            conn = sqlite3.connect(f'file:{chrome_history}?mode=ro', uri=True)
            cursor = conn.cursor()
            
            try:
                cursor.execute('SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT 1000')
                urls = [row[0] for row in cursor.fetchall()]
                
                adult_keywords = ['porn', 'xxx', 'adult', 'sex', 'hentai', 'nude', 'naked']
                suspicious_keywords = ['cheat', 'hack', 'crack', 'bypass', 'injector', 'warez']
                
                for url in urls:
                    url_lower = url.lower()
                    if any(kw in url_lower for kw in adult_keywords):
                        results['adult_content'].append(url)
                    elif any(kw in url_lower for kw in suspicious_keywords):
                        results['suspicious_sites'].append(url)
                
                if results['adult_content']:
                    results['risk_level'] = 'HIGH - Adult Content Found'
                elif results['suspicious_sites']:
                    results['risk_level'] = 'MEDIUM - Suspicious Sites'
            finally:
                conn.close()
    
    except Exception as e:
        results['error'] = str(e)
    
    return results

def scan_processes_ultra_fast() -> dict:
    """Ultra-fast process scanning"""
    results = {
        'malicious_processes': [],
        'risk_level': 'CLEAN'
    }
    
    try:
        import psutil
        
        malicious_keywords = ['cheatengine', 'autohotkey', 'ollydbg', 'x64dbg', 'ghidra', 'ida64', 'frida']
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                if any(kw in name for kw in malicious_keywords):
                    results['malicious_processes'].append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name']
                    })
            except:
                pass
        
        if results['malicious_processes']:
            results['risk_level'] = 'CRITICAL - Malicious Processes Found'
    
    except Exception as e:
        results['error'] = str(e)
    
    return results

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FLASK APP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 1000 * 1024 * 1024

UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "ss-tools-ultra")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ─── API Routes ───

@app.route('/')
def index():
    return render_template('index_ultra_modern.html')

@app.route('/api/scan/jar', methods=['POST'])
def scan_jar_api():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if not file.filename.endswith('.jar'):
        return jsonify({'error': 'File must be JAR'}), 400
    
    temp_path = os.path.join(UPLOAD_DIR, file.filename)
    file.save(temp_path)
    
    try:
        result = scan_jar_ultra_fast(temp_path)
        return jsonify(result)
    finally:
        try:
            os.remove(temp_path)
        except:
            pass

@app.route('/api/scan/minecraft-ultra-fast')
def scan_minecraft_ultra_fast_api():
    result = scan_minecraft_launchers_ultra_fast()
    return jsonify(result)

@app.route('/api/scan/browser')
def scan_browser_api():
    result = scan_browser_history_ultra_fast()
    return jsonify(result)

@app.route('/api/scan/processes')
def scan_processes_api():
    result = scan_processes_ultra_fast()
    return jsonify(result)

@app.route('/api/scan/full-ultra-fast')
def full_scan_ultra_fast_api():
    results = {
        'minecraft': scan_minecraft_launchers_ultra_fast(),
        'browser': scan_browser_history_ultra_fast(),
        'processes': scan_processes_ultra_fast(),
        'summary': {
            'total_scans': 3,
            'risk_level': 'CLEAN'
        }
    }
    
    # Determine overall risk
    if results['minecraft']['cheats_detected'] > 0:
        results['summary']['risk_level'] = 'CRITICAL'
    elif results['browser']['risk_level'] != 'CLEAN':
        results['summary']['risk_level'] = 'HIGH'
    elif results['processes']['risk_level'] != 'CLEAN':
        results['summary']['risk_level'] = 'CRITICAL'
    
    return jsonify(results)

@app.route('/api/jar/contents', methods=['POST'])
def jar_contents_api():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    temp_path = os.path.join(UPLOAD_DIR, file.filename)
    file.save(temp_path)
    
    try:
        result = {'files': [], 'scan': scan_jar_ultra_fast(temp_path)}
        
        with zipfile.ZipFile(temp_path, 'r') as jar:
            files = jar.namelist()[:200]
            for f in files:
                result['files'].append({
                    'name': f,
                    'type': 'class' if f.endswith('.class') else 'other'
                })
        
        return jsonify(result)
    finally:
        try:
            os.remove(temp_path)
        except:
            pass

@app.route('/api/scan/ghost-client', methods=['POST'])
def ghost_client_api():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    temp_path = os.path.join(UPLOAD_DIR, file.filename)
    file.save(temp_path)
    
    try:
        result = scan_jar_ultra_fast(temp_path)
        return jsonify(result)
    finally:
        try:
            os.remove(temp_path)
        except:
            pass

# ─── Server Start ───

if __name__ == '__main__':
    port = 8080
    
    try:
        import webview
        flask_thread = threading.Thread(
            target=lambda: app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
            daemon=True
        )
        flask_thread.start()
        time.sleep(1)
        
        webview.create_window(
            "SS Tools Ultra v3.0",
            f"http://127.0.0.1:{port}",
            width=1600,
            height=1000,
            resizable=True
        )
        webview.start(debug=False)
    except ImportError:
        print(f"Open http://localhost:{port} in browser")
        app.run(host="0.0.0.0", port=port, debug=False)
