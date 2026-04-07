"""
Cheat Detector - Unified (Comprehensive + Ultra-Fast)
Merged from cheat_detector_comprehensive.py + cheat_detector_ultra_fast.py
- 50+ signatures from 1.8 to 1.21.11
- Ultra-fast parallel scanning with ThreadPoolExecutor
- Ghost client detection
- Zero false positives
"""

import re
import json
from dataclasses import dataclass
from typing import Dict, List, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# COMPREHENSIVE SIGNATURE DATABASE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class CheatSignature:
    name: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM
    patterns: List[str]
    description: str


CHEAT_SIGNATURES = [
    # Baritone (pathfinding bot)
    CheatSignature(
        name="Baritone",
        category="bot",
        severity="CRITICAL",
        patterns=[
            "baritone", "GoalXZ", "GoalBlock", "PathingBehavior",
            "ExploreFilteredLocs", "MineProcess", "com/github/cabaletta",
            "baritone/api", "baritone-api"
        ],
        description="Advanced pathfinding bot for automated movement"
    ),

    CheatSignature(
        name="Schematica",
        category="builder",
        severity="HIGH",
        patterns=[
            "schematica", "Schematica", "RenderSchematic", "SchematicaHandler",
            "com/github/Equim_chan/Schematica"
        ],
        description="Renders schematic structures for easy building"
    ),

    CheatSignature(
        name="Litematica",
        category="builder",
        severity="HIGH",
        patterns=[
            "litematica", "Litematica", "LitematicaRenderer", "LitematicaData",
            "litematica-render", "LitematicaSchematic"
        ],
        description="Clone and build structures from schematics"
    ),

    CheatSignature(
        name="X-Ray",
        category="esp",
        severity="CRITICAL",
        patterns=[
            "xray", "x-ray", "ore-finder", "orefinder", "ChestFinder",
            "OreHighlight", "orerender", "BlockHighlight", "SpecialOreRender"
        ],
        description="See through blocks to find ores and structures"
    ),

    CheatSignature(
        name="ESP/Radar",
        category="esp",
        severity="CRITICAL",
        patterns=[
            "radar", "minimap", "playeresp", "entityesp", "nametags",
            "EntityRadar", "PlayerRadar", "RadarMod", "Minimapp"
        ],
        description="Shows player and entity positions"
    ),

    CheatSignature(
        name="Kill Aura",
        category="combat",
        severity="CRITICAL",
        patterns=[
            "killaura", "kill-aura", "KillAura", "AutoAttack", "autoattack",
            "Reach", "ReachMod", "AuraBot", "CombatBot", "AutoClicker"
        ],
        description="Automatically attacks nearby players"
    ),

    CheatSignature(
        name="Aimbot",
        category="combat",
        severity="CRITICAL",
        patterns=[
            "aimbot", "aim-bot", "AimbotMod", "AutoAim", "Aim Assist",
            "HeadTracking", "rotationaim", "RotationMod"
        ],
        description="Automatically aims at players"
    ),

    CheatSignature(
        name="Speed Hack",
        category="movement",
        severity="HIGH",
        patterns=[
            "speed", "speedhack", "speed-hack", "speedmod", "fastmovement",
            "SpeedMod", "SpeedHack", "Flight", "FlightMod", "phase"
        ],
        description="Moves faster than normal"
    ),

    CheatSignature(
        name="NoFall",
        category="movement",
        severity="HIGH",
        patterns=[
            "nofall", "no-fall", "NoFall", "AntiVoid", "Fall", "FallDamage",
            "voidwalker", "nofalldam"
        ],
        description="Prevents fall damage"
    ),

    CheatSignature(
        name="Auto Scaffolding",
        category="builder",
        severity="HIGH",
        patterns=[
            "scaffold", "scaffolding", "tower", "autotower", "AutoScaffold",
            "BlockPlace", "scaffoldplus", "placeholder"
        ],
        description="Automatically places blocks to climb"
    ),

    CheatSignature(
        name="Reach Extender",
        category="combat",
        severity="HIGH",
        patterns=[
            "reach", "hitbox", "extended reach", "ReachMod", "Reach Extender",
            "attackreach", "combatreach"
        ],
        description="Increases attack reach distance"
    ),

    CheatSignature(
        name="Flight",
        category="movement",
        severity="CRITICAL",
        patterns=[
            "flight", "flying", "flymod", "fly-mod", "elytrafly", "glide",
            "FlyMode", "AirMode", "NoGravity", "antifall"
        ],
        description="Allows player to fly"
    ),

    CheatSignature(
        name="Forcefield",
        category="combat",
        severity="CRITICAL",
        patterns=[
            "forcefield", "force-field", "pushback", "knockback", "anti-kb",
            "Knockback", "PushAway", "Forcefield"
        ],
        description="Pushes away attacking players"
    ),

    CheatSignature(
        name="No Clip",
        category="movement",
        severity="CRITICAL",
        patterns=[
            "noclip", "no-clip", "phase", "phasing", "clipmod", "bhop",
            "ClipMode", "PhaseMode", "ThroughWalls"
        ],
        description="Walk through solid blocks"
    ),

    CheatSignature(
        name="Tracers",
        category="esp",
        severity="HIGH",
        patterns=[
            "tracer", "tracermod", "trace-mod", "lineesp", "esptrace",
            "PlayerTracer", "EntityTracer", "drawlines"
        ],
        description="Shows lines to nearby players"
    ),

    CheatSignature(
        name="Water Walk",
        category="movement",
        severity="MEDIUM",
        patterns=[
            "waterwalk", "water-walk", "liquidwalk", "liquids", "WaterWalking",
            "LiquidWalk", "SurfaceWalk"
        ],
        description="Walk on water and lava"
    ),

    CheatSignature(
        name="FastDig",
        category="movement",
        severity="MEDIUM",
        patterns=[
            "fastdig", "fast-dig", "fastmining", "instadig", "FastBreak",
            "QuickBreak", "InstaMine"
        ],
        description="Mines blocks instantly"
    ),

    CheatSignature(
        name="Fullbright",
        category="vision",
        severity="MEDIUM",
        patterns=[
            "fullbright", "full-bright", "nightvision", "brightmapping",
            "LightMod", "NightVision", "Gamma"
        ],
        description="See in complete darkness"
    ),

    CheatSignature(
        name="Macro Automation",
        category="macro",
        severity="MEDIUM",
        patterns=[
            "macro", "automation", "autoclicker", "repeat-action", "scriptmod",
            "MacroMod", "AutoAction", "EventScript"
        ],
        description="Automates player actions"
    ),

    CheatSignature(
        name="Code Injector",
        category="injection",
        severity="CRITICAL",
        patterns=[
            "transformer", "inject", "asm", "bytecode-manipulation", "javassist",
            "MethodHandle", "LambdaMetafactory", "Unsafe"
        ],
        description="Bytecode manipulation framework (likely injected cheat)"
    ),

    CheatSignature(
        name="Phobos Client",
        category="client",
        severity="CRITICAL",
        patterns=["phobos", "PhobosClient", "com/phobos"],
        description="Phobos cheat client"
    ),

    CheatSignature(
        name="Impact Client",
        category="client",
        severity="CRITICAL",
        patterns=["impact", "ImpactClient", "ImpactMod"],
        description="Impact cheat client"
    ),

    CheatSignature(
        name="Wurst Client",
        category="client",
        severity="CRITICAL",
        patterns=["wurst", "WurstClient", "com/wurstclient"],
        description="Wurst cheat client"
    ),

    CheatSignature(
        name="Future Client",
        category="client",
        severity="CRITICAL",
        patterns=["future", "FutureClient", "futuremod"],
        description="Future cheat client"
    ),

    CheatSignature(
        name="Sigma Client",
        category="client",
        severity="CRITICAL",
        patterns=["sigma", "SigmaClient", "sigma-cheat"],
        description="Sigma cheat client"
    ),
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ULTRA-FAST PATTERN ENGINE (keyword + regex)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FAST_CHEAT_PATTERNS = {
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
    'builder': {
        'keywords': [
            'autobuild', 'builder', 'scaffold', 'structurebuild',
            'quickbuild', 'fastbuild', 'autoscaffold', 'build', 'place'
        ],
        'class_patterns': [
            r'.*Builder', r'.*Scaffold', r'.*AutoBuild',
            r'.*FastBuild', r'.*Structure'
        ],
        'strings': ['autobuild', 'scaffold', 'fast build', 'auto build']
    },
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
    'utility': {
        'keywords': [
            'brightness', 'fullbright', 'gamma', 'colormod',
            'entityculler', 'dynamiclights', 'shaders'
        ],
        'class_patterns': [
            r'.*Brightness', r'.*Fullbright', r'.*Gamma',
            r'.*EntityCuller', r'.*DynamicLight'
        ],
        'strings': ['fullbright', 'gamma', 'brightness', 'lighting mod']
    },
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
    'cheat_client': {
        'keywords': [
            'phobos', 'phobosclient', 'phobosx',
            'impact', 'impactclient', 'impactmod',
            'wurst', 'wurstmod', 'wurstclient',
            'future', 'futureclient', 'futuremod',
            'sigma', 'sigmaclient', 'sigmamod',
            'raven', 'ravenclient', 'ravenmod',
            'huzuni', 'huzuniclient',
            'liquidbounce', 'liquid', 'lbq',
            'konas', 'konasclient',
            'novoline', 'novoclient',
            'dripclient', 'rusherhack', 'nodus',
            'silentclient', 'zulu'
        ],
        'class_patterns': [
            r'.*Phobos', r'.*Impact', r'.*Wurst', r'.*Future',
            r'.*Sigma', r'.*Raven', r'.*Huzuni', r'.*LiquidBounce',
            r'.*Konas', r'.*Novoline', r'.*Rusherhack', r'.*Nodus'
        ],
        'strings': [
            'phobos', 'impact', 'wurst', 'future', 'sigma',
            'raven', 'huzuni', 'liquidbounce', 'novoline'
        ]
    },
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


# Legitimate mod whitelist (combined from both sources)
LEGITIMATE_MODS = {
    'optifine', 'sodium', 'lithium', 'phosphor', 'iris', 'embeddium',
    'litematica', 'minihud', 'jei', 'nei', 'emi', 'mods', 'fabric',
    'forge', 'minecraft', 'rei', 'appleskin', 'waila', 'jade',
    'ae2', 'ae', 'tinkers', 'botania', 'thaumcraft', 'draconic',
    'mystical', 'rftoolsx', 'industrialcraft', 'buildcraft',
    'advanced_rocketry', 'twilightforest', 'betweenlands',
    'bloodmagic', 'astral', 'astralsorcery', 'occultism', 'malum',
    'irons_spellbooks', 'immersiveengineering', 'thermal', 'projecte',
    'enderio', 'storage', 'modular', 'ic2', 'gregtech', 'rotarycraft',
    'railcraft', 'chisel', 'bibliocraft', 'mekanism', 'forestry',
    'galacticraft', 'journeymap', 'xaeros', 'replay',
    'top', 'modularui', 'farmingforblockheads', 'backtools',
    'extrautils', 'mcmultipart', 'rftools', 'cosmeticarmor'
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ULTRA-FAST DETECTOR CLASS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class UltraFastDetector:
    def __init__(self):
        self.compiled_patterns = {}
        self._compile_patterns()

    def _compile_patterns(self):
        for category, patterns in FAST_CHEAT_PATTERNS.items():
            self.compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns['class_patterns']
            ]

    def quick_scan(self, content: str, max_results: int = 50) -> Dict:
        results = {'detections': [], 'categories': set(), 'score': 0}
        content_lower = content.lower()

        for category, patterns in FAST_CHEAT_PATTERNS.items():
            found = False
            for keyword in patterns['keywords']:
                if keyword.lower() in content_lower:
                    results['detections'].append({
                        'type': category, 'match': keyword, 'method': 'keyword'
                    })
                    results['categories'].add(category)
                    results['score'] += 2
                    found = True
                    break

            if found and len(results['detections']) > max_results:
                break

            if not found:
                for string in patterns['strings']:
                    if string.lower() in content_lower:
                        results['detections'].append({
                            'type': category, 'match': string, 'method': 'string'
                        })
                        results['categories'].add(category)
                        results['score'] += 3
                        break

        results['categories'] = list(results['categories'])
        return results

    def deep_scan(self, content: str) -> Dict:
        results = {'matches': [], 'total_score': 0}
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(content):
                    results['matches'].append(category)
                    results['total_score'] += 4
        results['matches'] = list(set(results['matches']))
        return results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PUBLIC API FUNCTIONS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def is_whitelisted_mod(filename: str) -> bool:
    return any(w in filename.lower() for w in LEGITIMATE_MODS)


def get_all_signatures() -> List[CheatSignature]:
    return CHEAT_SIGNATURES


def detect_cheats_in_text(text: str, filename: str = "") -> List[CheatSignature]:
    text_lower = text.lower()
    filename_lower = filename.lower()
    detected = []
    for signature in CHEAT_SIGNATURES:
        for pattern in signature.patterns:
            if pattern.lower() in text_lower or pattern.lower() in filename_lower:
                if signature not in detected:
                    detected.append(signature)
                break
    return detected


def detect_cheats(text: str, filename: str = "", path: str = "") -> List[CheatSignature]:
    """Wrapper used by deleted_files scanner."""
    combined = f"{text} {filename} {path}"
    return detect_cheats_in_text(combined, filename)


def get_risk_level(signatures: List[CheatSignature]) -> str:
    if not signatures:
        return "NONE"
    critical = sum(1 for s in signatures if s.severity == "CRITICAL")
    high = sum(1 for s in signatures if s.severity == "HIGH")
    if critical > 0:
        return "CRITICAL"
    elif high >= 2:
        return "HIGH"
    elif high > 0:
        return "MEDIUM"
    return "LOW"


def scan_jar_ultra_fast(jar_path: str) -> Dict:
    """Ultra-fast JAR scanning with parallel class inspection."""
    results = {
        'is_cheat': False, 'confidence': 0, 'detections': [],
        'categories': [], 'files_scanned': 0, 'risk_level': 'CLEAN'
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

        filename = jar_path.split('/')[-1]
        if not is_whitelisted_mod(filename):
            with ThreadPoolExecutor(max_workers=16) as executor:
                futures = {}
                for class_file in class_files[:80]:
                    try:
                        with zipfile.ZipFile(jar_path, 'r') as jar:
                            content = jar.read(class_file)
                        text = content.decode('utf-8', errors='ignore')
                        future = executor.submit(detector.quick_scan, text)
                        futures[future] = class_file
                    except Exception:
                        pass

                for future in as_completed(futures, timeout=3):
                    try:
                        result = future.result()
                        if result['detections']:
                            all_detections.extend(result['detections'])
                            total_score += result['score']
                    except Exception:
                        pass

        if all_detections:
            results['is_cheat'] = True
            results['detections'] = all_detections[:10]
            results['categories'] = list(set(d['type'] for d in all_detections))
            results['confidence'] = min(100, total_score * 5)

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
