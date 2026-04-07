"""
Ghost Client Detector - Detect Argon, Wurst+, dan instant-speed clients
Specialized detection untuk client yang bisa disappear dari normal detection
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ghost Client Patterns - Argon, Wurst+, dan instant-speed clients
GHOST_PATTERNS = {
    # Argon Client
    'argon': {
        'keywords': [
            'argon', 'argonoclient', 'argon2k', 'argon_asm',
            'com/argon', 'net/argon', 'org/argon',
            'ArgonClient', 'ArgonModule', 'argon.module',
            'BindKey', 'ModuleManager', 'EventManager',
            'ARGON_VERSION', 'ARGON_BUILD'
        ],
        'strings': [
            'Argon Client', 'argon.net', 'argonbuild',
            'Argon Module', 'ArgonMod', 'ArgonUtil'
        ],
        'class_patterns': [
            r'class.*Argon.*Module',
            r'class.*Argon.*Event',
            r'class.*Argon.*Bind'
        ]
    },
    
    # Wurst+ (Extended Wurst)
    'wurst_plus': {
        'keywords': [
            'wurstplus', 'wurst+', 'wurst_plus', 'wurstplusplus',
            'com/wurst/plus', 'net/wurst/plus',
            'WurstPlus', 'WurstPlusModule', 'WurstPlusEvent',
            'wurstplusmod', 'wurst_extended'
        ],
        'strings': [
            'Wurst+', 'WurstPlus', 'Wurst Extended',
            'wurst-plus', 'wurstmod'
        ],
        'class_patterns': [
            r'class.*WurstPlus',
            r'class.*Wurst.*Extended'
        ]
    },
    
    # Instant Speed Clients (Hypixel bypass)
    'instant_speed': {
        'keywords': [
            'instantspeed', 'instant_speed', 'speedhack',
            'nofalldamage', 'velocityfix', 'motionfix',
            'InstantSpeed', 'SpeedModule', 'VelocityHack',
            'motionX', 'motionY', 'motionZ'
        ],
        'strings': [
            'instant speed', 'velocity fix', 'motion hack',
            'nofall', 'speed bypass', 'hypixel bypass'
        ],
        'class_patterns': [
            r'class.*InstantSpeed',
            r'class.*VelocityFix',
            r'class.*MotionHack'
        ]
    },
    
    # Generic Ghost Client Indicators
    'ghost_indicators': {
        'keywords': [
            'ghostclient', 'ghost_client', 'coilware',
            'injector', 'hooking', 'bytecode', 'asm_',
            'MethodHandle', 'ClassLoader', 'defineClass',
            'NativeMethod', 'JNI', 'native_', 'extern_'
        ],
        'strings': [
            'ghost client', 'hidden client', 'stealth mode',
            'bypass detection', 'anti-analysis', 'encryption'
        ],
        'class_patterns': [
            r'class.*Ghost',
            r'class.*Hidden',
            r'class.*Injector',
            r'class.*Hook'
        ]
    },
    
    # Hypixel Bypassers
    'hypixel_bypass': {
        'keywords': [
            'hypixelbypass', 'antiflyhack', 'antimod',
            'flagbypass', 'banbypass', 'detectbypass',
            'checkbypass', 'getbypass', 'disableflag'
        ],
        'strings': [
            'hypixel bypass', 'anti-flag', 'bypass detection',
            'skip check', 'disable check', 'flag bypass'
        ],
        'class_patterns': [
            r'class.*Bypass',
            r'class.*AntiFlag',
            r'class.*DisableCheck'
        ]
    }
}

def check_ghost_patterns(file_path: str) -> dict:
    """Check JAR/class file for ghost client patterns"""
    results = {'detected': False, 'ghosts': [], 'confidence': 0, 'details': []}
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Convert to string for pattern matching
        try:
            text_content = content.decode('utf-8', errors='ignore')
        except:
            text_content = str(content)
        
        found_patterns = set()
        confidence_score = 0
        
        for ghost_type, patterns in GHOST_PATTERNS.items():
            matches = {'keywords': [], 'strings': [], 'classes': []}
            
            # Check keywords
            for keyword in patterns.get('keywords', []):
                if keyword.lower() in text_content.lower():
                    matches['keywords'].append(keyword)
                    confidence_score += 2
            
            # Check strings
            for string in patterns.get('strings', []):
                if string.lower() in text_content.lower():
                    matches['strings'].append(string)
                    confidence_score += 3
            
            # Check class patterns
            for pattern in patterns.get('class_patterns', []):
                if re.search(pattern, text_content, re.IGNORECASE):
                    matches['classes'].append(pattern)
                    confidence_score += 4
            
            if matches['keywords'] or matches['strings'] or matches['classes']:
                found_patterns.add(ghost_type)
                results['details'].append({
                    'type': ghost_type,
                    'keywords': matches['keywords'],
                    'strings': matches['strings'],
                    'classes': matches['classes']
                })
        
        if found_patterns:
            results['detected'] = True
            results['ghosts'] = list(found_patterns)
            results['confidence'] = min(100, confidence_score)
    
    except Exception as e:
        pass
    
    return results

def scan_for_ghost_clients(jar_path: str, max_workers: int = 8) -> dict:
    """Parallel scan JAR for ghost clients"""
    results = {
        'ghost_clients': [],
        'suspicion_level': 'CLEAN',
        'confidence': 0,
        'files_checked': 0,
        'detections': []
    }
    
    try:
        import zipfile
        
        with zipfile.ZipFile(jar_path, 'r') as jar:
            class_files = [f for f in jar.namelist() if f.endswith('.class')]
        
        if not class_files:
            return results
        
        results['files_checked'] = len(class_files)
        total_confidence = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            
            for class_file in class_files[:100]:  # Limit to 100 files for speed
                temp_path = f"/tmp/{class_file.split('/')[-1]}"
                try:
                    with zipfile.ZipFile(jar_path, 'r') as jar:
                        with open(temp_path, 'wb') as f:
                            f.write(jar.read(class_file))
                    
                    future = executor.submit(check_ghost_patterns, temp_path)
                    futures[future] = class_file
                except:
                    pass
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=2)
                    if result['detected']:
                        results['detections'].append({
                            'file': futures[future],
                            'ghosts': result['ghosts'],
                            'confidence': result['confidence']
                        })
                        total_confidence += result['confidence']
                except:
                    pass
        
        if results['detections']:
            results['ghost_clients'] = list(set(
                g for d in results['detections'] for g in d['ghosts']
            ))
            avg_confidence = total_confidence / len(results['detections'])
            
            if avg_confidence > 80:
                results['suspicion_level'] = 'CRITICAL - Ghost Client Detected'
            elif avg_confidence > 50:
                results['suspicion_level'] = 'HIGH - Likely Ghost Client'
            elif avg_confidence > 20:
                results['suspicion_level'] = 'MEDIUM - Suspicious Patterns'
            
            results['confidence'] = int(avg_confidence)
    
    except Exception as e:
        pass
    
    return results

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = scan_for_ghost_clients(sys.argv[1])
        print(json.dumps(result, indent=2))
