"""
Ultra-Fast Cheat Detector - Optimized for instant detection
Includes ghost client detection, improved keywords, parallel inspection
"""

import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

# Ultra-expanded cheat signatures (1.8 - 1.21.11)
CHEAT_SIGNATURES = {
    # Combat Enhancement
    'combat': {
        'keywords': [
            'criticalstrike', 'autoclicker', 'click', 'cps', 'killaura',
            'aura', 'aimbot', 'aimassist', 'velocity', 'combatlogger',
            'combatloop', 'autoattack', 'fastheal', 'autohealth', 'healthboost'
        ],
        'class_patterns': [
            r'.*Aura', r'.*Clicker', r'.*Combat', r'.*KillAura',
            r'.*AutoAttack', r'.*CriticalStrike', r'.*Velocity'
        ],
        'strings': ['killaura', 'aimbot', 'auto attack', 'critical strike', 'velocity']
    },
    
    # Movement Hacks
    'movement': {
        'keywords': [
            'speed', 'flight', 'noclip', 'teleport', 'strafe', 'scaffold',
            'move', 'motion', 'velocity', 'boost', 'blink', 'step', 'nofall',
            'waterwalk', 'spiderwalk', 'climb', 'fly', 'glide'
        ],
        'class_patterns': [
            r'.*Speed', r'.*Flight', r'.*Fly', r'.*Step',
            r'.*Scaffold', r'.*NoFall', r'.*BLink'
        ],
        'strings': ['speed hack', 'flight', 'noclip', 'teleport', 'scaffold']
    },
    
    # Vision/Esp
    'vision': {
        'keywords': [
            'esp', 'xray', 'radar', 'tracers', 'wallhack', 'skeleton',
            'glow', 'highlight', 'entityesp', 'playeresp', 'render',
            'vision', 'see', 'peek', 'camera', 'view'
        ],
        'class_patterns': [
            r'.*Esp', r'.*Xray', r'.*Radar', r'.*Tracers',
            r'.*WallHack', r'.*Skeleton', r'.*Glow'
        ],
        'strings': ['esp', 'xray', 'wallhack', 'skeleton', 'tracers']
    },
    
    # Builder/AutoTool
    'builder': {
        'keywords': [
            'autobuild', 'builder', 'scaffold', 'structurebuild',
            'autobuild', 'quickbuild', 'fastbuild', 'autoscaffold',
            'build', 'place', 'block', 'construct'
        ],
        'class_patterns': [
            r'.*Builder', r'.*Scaffold', r'.*AutoBuild',
            r'.*FastBuild', r'.*Structure'
        ],
        'strings': ['autobuild', 'scaffold', 'fast build', 'auto build']
    },
    
    # Macro/Bot
    'macro': {
        'keywords': [
            'macro', 'bot', 'autoclick', 'autofarm', 'autorep',
            'autofish', 'autominer', 'automine', 'autofight',
            'autopet', 'autotrader', 'autobuyer', 'automsg'
        ],
        'class_patterns': [
            r'.*Macro', r'.*Bot', r'.*Auto.*', r'.*Farm',
            r'.*Miner', r'.*Fisher'
        ],
        'strings': ['macro', 'bot', 'autofarm', 'autofish', 'autominer']
    },
    
    # Modifications/Utility
    'utility': {
        'keywords': [
            'brightness', 'fullbright', 'gamma', 'colormod',
            'entityculler', 'dynamiclights', 'shaders', 'brightness',
            'visibility', 'render', 'gamma', 'lighting'
        ],
        'class_patterns': [
            r'.*Brightness', r'.*Fullbright', r'.*Gamma',
            r'.*EntityCuller', r'.*DynamicLight'
        ],
        'strings': ['fullbright', 'gamma', 'brightness', 'lighting mod']
    },
    
    # Injection/Hooking (Critical)
    'injection': {
        'keywords': [
            'inject', 'hook', 'bytecode', 'asm', 'reflection',
            'methodhandle', 'invokespecial', 'defineclass',
            'jni', 'native', 'extern', 'hook_', 'patch_'
        ],
        'class_patterns': [
            r'.*Inject', r'.*Hook', r'.*Bytecode', r'.*Asm',
            r'.*Reflection', r'.*MethodHandle'
        ],
        'strings': ['injection', 'hook', 'bytecode', 'asm', 'reflection']
    },
    
    # Known Cheat Clients
    'cheat_client': {
        'keywords': [
            # Phobos
            'phobos', 'phobosclient', 'phobosx', 'phobos_',
            # Impact
            'impact', 'impactclient', 'impactmod',
            # Wurst
            'wurst', 'wurstmod', 'wurstclient', 'wurst_',
            # Future
            'future', 'futureclient', 'futuremod',
            # Sigma
            'sigma', 'sigmaclient', 'sigmamod',
            # Raven
            'raven', 'ravenclient', 'ravenmod', 'ravenb+',
            # Huzuni
            'huzuni', 'huzuniclient',
            # Liquidbounce
            'liquidbounce', 'liquid', 'lbq',
            # Konas
            'konas', 'konasclient',
            # Novoline
            'novoline', 'novoclient',
            # Drip
            'dripclient', 'dripmod',
            # Retail
            'retail', 'retailmod',
            # Rusherhack
            'rusherhack', 'rusher',
            # Nodus
            'nodus', 'nodusclient',
            # SilentClient
            'silentclient', 'silent',
            # Zulu
            'zulu', 'zulumod'
        ],
        'class_patterns': [
            r'.*Phobos', r'.*Impact', r'.*Wurst', r'.*Future',
            r'.*Sigma', r'.*Raven', r'.*Huzuni', r'.*LiquidBounce',
            r'.*Konas', r'.*Novoline', r'.*Drip', r'.*Rusherhack',
            r'.*Nodus', r'.*SilentClient', r'.*Zulu'
        ],
        'strings': [
            'phobos', 'impact', 'wurst', 'future', 'sigma',
            'raven', 'huzuni', 'liquidbounce', 'novoline'
        ]
    },
    
    # Ghost Client Specific
    'ghost_client': {
        'keywords': [
            'argon', 'argonoclient', 'coilware', 'ghostclient',
            'instantspeed', 'hypixelbypass', 'wurstplus', 'wurst+',
            'stealth', 'hidden', 'ghost', 'bypass', 'injector'
        ],
        'class_patterns': [
            r'.*Argon', r'.*Ghost', r'.*Stealth', r'.*Injector',
            r'.*Bypass', r'.*Hidden'
        ],
        'strings': ['argon', 'ghost client', 'stealth', 'bypass', 'instant']
    }
}

# Legitimate mod whitelist - won't flag these
LEGITIMATE_MODS = {
    'optifine', 'sodium', 'iris', 'litematica', 'minihud',
    'jei', 'emi', 'mods', 'fabric', 'forge', 'minecraft',
    'rei', 'appleskin', 'waila', 'jade', 'ae2', 'ae', 'tinkers',
    'botania', 'thaumcraft', 'draconic', 'mystical', 'rftoolsx',
    'industrialcraft', 'buildcraft', 'advanced_rocketry',
    'twilightforest', 'betweenlands', 'bloodmagic', 'astral',
    'astralsorcery', 'occultism', 'malum', 'irons_spellbooks',
    'immersiveengineering', 'thermal', 'projecte', 'enderio',
    'storage', 'modular', 'ic2', 'gregtech', 'rotarycraft',
    'railcraft', 'chisel', 'bibliocraft', 'bibliocraft'
}

class UltraFastDetector:
    def __init__(self):
        self.compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for speed"""
        for category, patterns in CHEAT_SIGNATURES.items():
            self.compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns['class_patterns']
            ]
    
    def quick_scan(self, content: str, max_results: int = 50) -> Dict:
        """Ultra-fast scan - hash-based string matching"""
        results = {'detections': [], 'categories': set(), 'score': 0}
        
        # Convert to lowercase once
        content_lower = content.lower()
        
        for category, patterns in CHEAT_SIGNATURES.items():
            found = False
            
            # Fast keyword check
            for keyword in patterns['keywords']:
                if keyword.lower() in content_lower:
                    results['detections'].append({
                        'type': category,
                        'match': keyword,
                        'method': 'keyword'
                    })
                    results['categories'].add(category)
                    results['score'] += 2
                    found = True
                    break
            
            if found and len(results['detections']) > max_results:
                break
            
            # Fast string check
            if not found:
                for string in patterns['strings']:
                    if string.lower() in content_lower:
                        results['detections'].append({
                            'type': category,
                            'match': string,
                            'method': 'string'
                        })
                        results['categories'].add(category)
                        results['score'] += 3
                        break
        
        results['categories'] = list(results['categories'])
        return results
    
    def is_legitimate_mod(self, filename: str) -> bool:
        """Quick whitelist check"""
        filename_lower = filename.lower()
        return any(mod in filename_lower for mod in LEGITIMATE_MODS)
    
    def deep_scan(self, content: str) -> Dict:
        """Detailed pattern matching"""
        results = {'matches': [], 'total_score': 0}
        
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(content):
                    results['matches'].append(category)
                    results['total_score'] += 4
        
        results['matches'] = list(set(results['matches']))
        return results

def scan_jar_ultra_fast(jar_path: str) -> Dict:
    """Ultra-fast JAR scanning with parallel class inspection"""
    results = {
        'is_cheat': False,
        'confidence': 0,
        'detections': [],
        'categories': [],
        'files_scanned': 0,
        'risk_level': 'CLEAN'
    }
    
    try:
        import zipfile
        
        detector = UltraFastDetector()
        
        with zipfile.ZipFile(jar_path, 'r') as jar:
            class_files = [f for f in jar.namelist() 
                          if f.endswith('.class') and not f.startswith('META-INF/')]
        
        if not class_files:
            return results
        
        results['files_scanned'] = len(class_files)
        total_score = 0
        all_detections = []
        
        # Check filename first (fast path)
        filename = jar_path.split('/')[-1]
        if not detector.is_legitimate_mod(filename):
            # Parallel scan with ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=16) as executor:
                futures = {}
                
                for class_file in class_files[:80]:  # Limit for speed
                    try:
                        with zipfile.ZipFile(jar_path, 'r') as jar:
                            content = jar.read(class_file)
                        
                        # Quick decode
                        try:
                            text = content.decode('utf-8', errors='ignore')
                        except:
                            text = str(content)
                        
                        future = executor.submit(detector.quick_scan, text)
                        futures[future] = class_file
                    except:
                        pass
                
                # Collect results with timeout
                for future in as_completed(futures, timeout=3):
                    try:
                        result = future.result()
                        if result['detections']:
                            all_detections.extend(result['detections'])
                            total_score += result['score']
                    except:
                        pass
        
        if all_detections:
            results['is_cheat'] = True
            results['detections'] = all_detections[:10]  # Top 10
            results['categories'] = list(set(d['type'] for d in all_detections))
            results['confidence'] = min(100, total_score * 5)
            
            # Determine risk level
            if 'cheat_client' in results['categories'] or 'ghost_client' in results['categories']:
                results['risk_level'] = 'CRITICAL - Known Cheat Client'
            elif 'injection' in results['categories']:
                results['risk_level'] = 'CRITICAL - Code Injection Detected'
            elif results['confidence'] > 80:
                results['risk_level'] = 'HIGH - Strong Cheat Indicators'
            elif results['confidence'] > 50:
                results['risk_level'] = 'MEDIUM - Suspicious Patterns'
            else:
                results['risk_level'] = 'LOW - Minor Detection'
    
    except Exception as e:
        results['error'] = str(e)
    
    return results

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = scan_jar_ultra_fast(sys.argv[1])
        print(json.dumps(result, indent=2, default=str))
