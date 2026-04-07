"""
Comprehensive Minecraft Cheat Detection Engine
Covers 1.21 - 1.21.11 cheat clients, macros, and injection tools.
Uses strict signature matching to avoid false flags.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class CheatSignature:
    name: str
    category: str
    severity: str  # "critical", "high", "medium", "low"
    description: str
    class_patterns: List[str] = field(default_factory=list)
    string_patterns: List[str] = field(default_factory=list)
    file_patterns: List[str] = field(default_factory=list)
    package_patterns: List[str] = field(default_factory=list)
    # Require minimum matches to avoid false flags
    min_matches: int = 2

@dataclass
class DetectionResult:
    flagged: bool
    signature_name: str
    category: str
    severity: str
    description: str
    matched_patterns: List[str]
    match_count: int
    file_path: str
    confidence: float  # 0.0 - 1.0


# ============================================================
# WHITELIST - Legitimate mods that must NEVER be flagged
# ============================================================
WHITELISTED_MODS = {
    # Performance
    "sodium", "lithium", "phosphor", "starlight", "ferritecore",
    "lazydfu", "smoothboot", "entityculling", "memoryleakfix",
    "modernfix", "immediatelyfast", "nvidium", "exordium",
    # Rendering / Shaders
    "optifine", "iris", "oculus", "canvas",
    # API / Library
    "fabric-api", "fabricapi", "fabric_api", "forgeconfigapiport",
    "architectury", "cloth-config", "clothconfig", "modmenu",
    "midnightlib", "iceberg", "puzzleslib", "balm", "bookshelf",
    "geckolib", "playeranimator", "azurelib", "creativecore",
    "kotlinforforge", "kotlin-stdlib", "fabric-language-kotlin",
    "sinytraconnector", "connector", "forgifiedfabricapi",
    # HUD / Info
    "journeymap", "xaero", "xaerominimap", "xaerosworldmap",
    "voxelmap", "betterpingdisplay", "appleskin", "jade",
    "wthit", "hwyla", "rei", "roughlyenoughitems", "jei",
    "emi", "tooltipfix", "betterf3", "minimap",
    # Cosmetic
    "capes", "customskinloader", "skinlayers3d", "ears",
    "cosmetica", "fabulousclouds", "effectivemc", "visuality",
    "particlerain", "fallingleaves", "illuminations",
    "lambdynamiclights", "dynamiclights", "continuity",
    "connectedness", "betterconnectedtextures",
    # Sound
    "soundphysics", "presencefootsteps", "ambientsounds",
    "extrasounds", "dynamicsoundfilters",
    # Utility
    "inventorysorter", "mousewheelie", "itemscroller",
    "litematica", "malilib", "minihud", "tweakeroo",
    "itemswapper", "zoomify", "okzoomer", "wizoom",
    "logical-zoom", "freecam", "replaymod", "replay",
    "screencapper", "screenshot", "fabrishot", "authme",
    "notenoughcrashes", "bettercrashes", "yosbr", "debugify",
    # Gameplay
    "sodium-extra", "indium", "reeses-sodium-options",
    "borderlessmining", "fullscreenwindowed", "dynamicfps",
    "cull-less-leaves", "enhancedblockentities", "betterbeds",
    "clumps", "fastload", "ksyxis", "servercore",
    # Chat
    "chatheads", "stendhal", "chatpatches", "nochatreports",
    # Other common legitimate
    "controlify", "midnightcontrols", "lambdacontrols",
    "bettercommandblockui", "worldedit", "axiom",
    "voicechat", "plasmovoice", "simplevoicechat",
    "emotecraft", "lambdabettergrass", "bettergrass",
    "cit-resewn", "citresewn", "animatica", "entitytexturefeatures",
    "morechathistory", "advancementinfo", "shulkerboxtooltip",
    "bedrockify", "recipebook", "craftpresence",
    "betteradvancements", "waystones", "betterstats",
    "spark", "bobby", "distanthorizons", "distant-horizons",
    "c2me", "c2me-fabric", "noisium",
}

# ============================================================
# MOD AUTHENTICITY VERIFICATION
# Maps whitelisted mod names -> expected package prefixes / class paths
# If a JAR claims to be "sodium" but has NONE of these packages,
# it's a disguised cheat.
# ============================================================
WHITELISTED_MOD_FINGERPRINTS: Dict[str, List[str]] = {
    "sodium": ["me/jellysquid/mods/sodium", "net/caffeinemc/mods/sodium", "cafe/sodium"],
    "lithium": ["me/jellysquid/mods/lithium", "net/caffeinemc/mods/lithium"],
    "phosphor": ["me/jellysquid/mods/phosphor"],
    "starlight": ["ca/spottedleaf/starlight"],
    "ferritecore": ["say/dl/ferritecore"],
    "iris": ["net/coderbot/iris", "net/irisshaders"],
    "optifine": ["net/optifine", "optifine/"],
    "fabric-api": ["net/fabricmc/fabric"],
    "fabricapi": ["net/fabricmc/fabric"],
    "modmenu": ["com/terraformersmc/modmenu"],
    "cloth-config": ["me/shedaniel/clothconfig"],
    "clothconfig": ["me/shedaniel/clothconfig"],
    "journeymap": ["journeymap/"],
    "xaero": ["xaero/"],
    "xaerominimap": ["xaero/minimap", "xaero/common"],
    "xaerosworldmap": ["xaero/map"],
    "rei": ["me/shedaniel/rei"],
    "roughlyenoughitems": ["me/shedaniel/rei"],
    "jei": ["mezz/jei"],
    "emi": ["dev/emi"],
    "jade": ["snownee/jade"],
    "appleskin": ["squeek/appleskin"],
    "litematica": ["fi/dy/masa/litematica"],
    "malilib": ["fi/dy/masa/malilib"],
    "minihud": ["fi/dy/masa/minihud"],
    "tweakeroo": ["fi/dy/masa/tweakeroo"],
    "replaymod": ["com/replaymod"],
    "worldedit": ["com/sk89q/worldedit"],
    "voicechat": ["de/maxhenkel/voicechat"],
    "plasmovoice": ["su/plo/voice"],
    "simplevoicechat": ["de/maxhenkel/voicechat"],
    "spark": ["me/lucko/spark"],
    "bobby": ["de/johni0702/minecraft/bobby"],
    "distanthorizons": ["com/seibel/distanthorizons"],
    "distant-horizons": ["com/seibel/distanthorizons"],
    "architectury": ["dev/architectury"],
    "geckolib": ["software/bernie/geckolib"],
    "continuity": ["me/pepperbell/continuity"],
    "entityculling": ["dev/tr7zw/entityculling"],
    "debugify": ["dev/isxander/debugify"],
    "zoomify": ["dev/isxander/zoomify"],
    "lambdynamiclights": ["dev/lambdaurora/lambdynlights"],
    "nochatreports": ["com/aizistral/nochatreports"],
    "soundphysics": ["com/sonicether/soundphysics"],
    "c2me": ["com/ishland/c2me"],
    "noisium": ["io/github/steveplays28/noisium"],
    "modernfix": ["org/embeddedt/modernfix"],
    "immediatelyfast": ["net/raphimc/immediatelyfast"],
    "indium": ["link/infra/indium"],
    "dynamicfps": ["net/lostluma/dynamicfps", "juliand665/dynamicfps"],
    "controlify": ["dev/isxander/controlify"],
    "axiom": ["com/moulberry/axiom"],
    "emotecraft": ["io/github/kosmx/emotes"],
    "presencefootsteps": ["eu/ha3/presencefootsteps"],
    "skinlayers3d": ["dev/tr7zw/skinlayers"],
}


def verify_mod_authenticity(filename: str, class_files: List[str]) -> Dict:
    """
    Verify if a JAR that matches a whitelisted mod name actually
    contains the expected package structure for that mod.

    Returns:
        {
            "claimed_mod": str or None,
            "is_authentic": bool,
            "expected_packages": list,
            "found_matching": list,
            "confidence": float,
        }
    """
    result = {
        "claimed_mod": None,
        "is_authentic": True,
        "expected_packages": [],
        "found_matching": [],
        "confidence": 1.0,
    }

    # Find which whitelisted mod this filename claims to be
    name_lower = filename.lower().replace(" ", "").replace("-", "").replace("_", "")
    matched_mod = None
    for wl in WHITELISTED_MODS:
        clean = wl.replace("-", "").replace("_", "")
        if clean in name_lower:
            matched_mod = wl
            break

    if not matched_mod:
        return result  # Not claiming to be whitelisted, skip

    result["claimed_mod"] = matched_mod

    # Check if we have fingerprints for this mod
    fingerprints = WHITELISTED_MOD_FINGERPRINTS.get(matched_mod)
    if not fingerprints:
        # No fingerprint data — can't verify, but don't skip inspection
        result["is_authentic"] = True  # Benefit of the doubt, but still scan contents
        result["confidence"] = 0.5
        return result

    result["expected_packages"] = fingerprints

    # Check if ANY class file matches the expected package structure
    class_paths_joined = " ".join(class_files).lower()
    found = []
    for fp in fingerprints:
        fp_lower = fp.lower().rstrip("/")
        if fp_lower in class_paths_joined:
            found.append(fp)

    result["found_matching"] = found

    if len(found) == 0 and len(class_files) > 0:
        # Has class files but NONE match expected packages → DISGUISED
        result["is_authentic"] = False
        result["confidence"] = 0.0
    elif len(found) == 0 and len(class_files) == 0:
        # Empty JAR or resource-only — suspicious but not definitive
        result["is_authentic"] = False
        result["confidence"] = 0.2
    else:
        result["is_authentic"] = True
        result["confidence"] = min(1.0, len(found) / len(fingerprints))

    return result


# ============================================================
# CHEAT CLIENT SIGNATURES - Very specific patterns
# ============================================================

CHEAT_SIGNATURES: List[CheatSignature] = [
    # ---- CRYSTAL PVP CHEATS ----
    CheatSignature(
        name="AutoCrystal Module",
        category="Crystal PvP",
        severity="critical",
        description="Automated end crystal placement and detonation",
        class_patterns=[
            "AutoCrystal.class", "CrystalAura.class", "AutoCrystalRewrite.class",
            "CrystalPlacer.class", "CrystalBreaker.class", "CEAura.class",
            "AutoCrystalHack.class", "CrystalAuraModule.class",
        ],
        string_patterns=[
            "autocrystal", "crystalaura", "crystal_aura", "auto_crystal",
            "crystalPlacer", "crystalBreaker", "crystalSpeed",
            "placeDelay", "breakDelay", "crystalRange", "placeCrystal",
            "breakCrystal", "antiWeakness", "switchDelay", "crystalpvp.autoplace",
            "facePlaceCrystal", "wallRange", "inhibitCrystals",
        ],
        package_patterns=[
            "module/combat/AutoCrystal", "module/combat/CrystalAura",
            "modules/crystal", "hack/combat/crystal",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="AnchorMacro / AutoAnchor",
        category="Crystal PvP",
        severity="critical",
        description="Automated respawn anchor exploit for PvP",
        class_patterns=[
            "AnchorMacro.class", "AutoAnchor.class", "AnchorAura.class",
            "RespawnAnchorExploit.class", "AnchorPlace.class",
        ],
        string_patterns=[
            "anchormacro", "autoanchor", "anchor_macro", "auto_anchor",
            "anchoraura", "anchor_aura", "anchorCharge", "anchorExplode",
            "placeAnchor", "chargeAnchor", "respawnAnchorAura",
        ],
        package_patterns=[
            "module/combat/AnchorMacro", "module/combat/AutoAnchor",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="BedAura / AutoBed",
        category="Crystal PvP",
        severity="critical",
        description="Automated bed bombing for PvP",
        class_patterns=[
            "BedAura.class", "AutoBed.class", "BedBomb.class",
            "BedExploit.class", "BedFight.class",
        ],
        string_patterns=[
            "bedaura", "autobed", "bed_aura", "auto_bed", "bedBomb",
            "bedExplode", "placeBed", "bedDelay", "bedRange",
        ],
        package_patterns=[
            "module/combat/BedAura", "module/combat/AutoBed",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Surround / AutoTrap",
        category="Crystal PvP",
        severity="high",
        description="Automatic obsidian surrounding / trapping players",
        class_patterns=[
            "Surround.class", "AutoTrap.class", "SelfTrap.class",
            "HoleFiller.class", "AutoObsidian.class", "SurroundModule.class",
        ],
        string_patterns=[
            "surround", "autotrap", "auto_trap", "selftrap", "holefiller",
            "surroundObsidian", "trapRange", "autoSurround",
        ],
        package_patterns=[
            "module/combat/Surround", "module/combat/AutoTrap",
        ],
        min_matches=2,
    ),

    # ---- SWORD PVP / COMBAT CHEATS ----
    CheatSignature(
        name="AimAssist / AimBot",
        category="Sword PvP",
        severity="critical",
        description="Automatic aim correction towards players",
        class_patterns=[
            "AimAssist.class", "AimBot.class", "AimAssistHack.class",
            "AutoAim.class", "AimLock.class", "SilentAim.class",
        ],
        string_patterns=[
            "aimassist", "aimbot", "aim_assist", "aim_bot", "autoaim",
            "aimSpeed", "aimRange", "fov_check", "aimFov", "targetFov",
            "aimSmooth", "silentAim", "aimLock", "aimPriority",
            "rotationSpeed", "aimAssistRange", "aimYaw", "aimPitch",
        ],
        package_patterns=[
            "module/combat/AimAssist", "module/combat/AimBot",
            "hack/combat/AimAssist", "modules/combat/aimassist",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="KillAura / ForceField",
        category="Sword PvP",
        severity="critical",
        description="Automatic attack on nearby entities",
        class_patterns=[
            "KillAura.class", "ForceField.class", "Aura.class",
            "KillAuraModule.class", "MultiAura.class", "TriggerAura.class",
        ],
        string_patterns=[
            "killaura", "forcefield", "kill_aura", "force_field",
            "auraRange", "auraDelay", "auraSpeed", "attackDelay",
            "swingRange", "hitRange", "autoAttack", "auraTargets",
            "targetPlayers", "targetMobs", "auraRotation", "auraSwitch",
        ],
        package_patterns=[
            "module/combat/KillAura", "module/combat/ForceField",
            "hack/combat/KillAura", "modules/combat/killaura",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Triggerbot",
        category="Sword PvP",
        severity="critical",
        description="Automatic attack when crosshair is on target",
        class_patterns=[
            "Triggerbot.class", "TriggerBot.class", "AutoClick.class",
            "TriggerBotModule.class",
        ],
        string_patterns=[
            "triggerbot", "trigger_bot", "triggerbotDelay",
            "triggerbotRange", "triggerHit", "autoSwing", "triggerCps",
        ],
        package_patterns=[
            "module/combat/Triggerbot", "module/combat/TriggerBot",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Reach Hack",
        category="Sword PvP",
        severity="critical",
        description="Extended attack/interaction reach distance",
        class_patterns=[
            "Reach.class", "ReachHack.class", "HitboxExpand.class",
            "LongArm.class", "ReachModule.class",
        ],
        string_patterns=[
            "reachHack", "reachDistance", "extraReach", "reachModifier",
            "hitboxExpand", "combatReach", "reachValue", "longarm",
        ],
        package_patterns=[
            "module/combat/Reach", "hack/combat/Reach",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Velocity / AntiKnockback",
        category="Sword PvP",
        severity="critical",
        description="Reduces or eliminates knockback from attacks",
        class_patterns=[
            "Velocity.class", "AntiKnockback.class", "AntiKB.class",
            "NoKnockback.class", "VelocityModule.class",
        ],
        string_patterns=[
            "velocity", "antiknockback", "anti_knockback", "antikb",
            "anti_kb", "noknockback", "velocityHorizontal", "velocityVertical",
            "knockbackReduction", "velocityCancel",
        ],
        package_patterns=[
            "module/combat/Velocity", "module/combat/AntiKnockback",
            "module/movement/Velocity",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="AutoTotem",
        category="Sword PvP",
        severity="high",
        description="Automatically places totem in offhand",
        class_patterns=[
            "AutoTotem.class", "TotemPopCounter.class", "OffhandTotem.class",
            "AutoTotemModule.class",
        ],
        string_patterns=[
            "autototem", "auto_totem", "totemSwitch", "offhandTotem",
            "totemDelay", "autoOffhand", "totemPriority",
        ],
        package_patterns=[
            "module/combat/AutoTotem", "module/player/AutoTotem",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="AutoClicker (Cheat-Level)",
        category="Sword PvP",
        severity="high",
        description="Automated clicking beyond normal CPS",
        class_patterns=[
            "AutoClicker.class", "FastClick.class", "AutoClickerModule.class",
        ],
        string_patterns=[
            "autoclicker", "auto_clicker", "clickSpeed", "maxCps",
            "minCps", "leftAutoClick", "rightAutoClick", "jitterClick",
            "clickRandomize", "autoClickDelay",
        ],
        package_patterns=[
            "module/combat/AutoClicker", "module/player/AutoClicker",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="W-Tap / Combo",
        category="Sword PvP",
        severity="medium",
        description="Automated W-tap sprint reset for combos",
        class_patterns=[
            "WTap.class", "AutoSprint.class", "Combo.class",
            "SprintReset.class", "WTapModule.class",
        ],
        string_patterns=[
            "wtap", "w_tap", "sprintReset", "autoSprint", "comboMode",
            "wtapDelay", "resetSprint", "tapDelay",
        ],
        package_patterns=[
            "module/combat/WTap", "module/movement/AutoSprint",
        ],
        min_matches=2,
    ),

    # ---- MOVEMENT CHEATS ----
    CheatSignature(
        name="Speed Hack",
        category="Movement",
        severity="critical",
        description="Increases movement speed beyond normal",
        class_patterns=[
            "Speed.class", "SpeedHack.class", "SpeedModule.class",
            "FastWalk.class", "BHop.class",
        ],
        string_patterns=[
            "speedHack", "speedMode", "speedValue", "speedBoost",
            "bhop", "bunnyHop", "timerSpeed", "groundSpeed",
            "strafeSpeed", "speedBypass",
        ],
        package_patterns=[
            "module/movement/Speed", "hack/movement/Speed",
        ],
        min_matches=3,
    ),
    CheatSignature(
        name="Fly Hack",
        category="Movement",
        severity="critical",
        description="Allows flying in survival mode",
        class_patterns=[
            "Fly.class", "FlyHack.class", "Flight.class",
            "FlyModule.class", "CreativeFly.class",
        ],
        string_patterns=[
            "flyHack", "flySpeed", "flyMode", "flightSpeed",
            "flyGlide", "flyKick", "flyBypass", "flyAntiKick",
            "flyPacket", "verticalSpeed",
        ],
        package_patterns=[
            "module/movement/Fly", "module/movement/Flight",
            "hack/movement/Fly",
        ],
        min_matches=3,
    ),
    CheatSignature(
        name="NoFall",
        category="Movement",
        severity="high",
        description="Prevents fall damage",
        class_patterns=[
            "NoFall.class", "AntiFall.class", "NoFallDamage.class",
            "NoFallModule.class",
        ],
        string_patterns=[
            "nofall", "no_fall", "antiFall", "noFallDamage",
            "noFallPacket", "cancelFall", "fallPacket",
        ],
        package_patterns=[
            "module/movement/NoFall", "module/player/NoFall",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Step / Spider",
        category="Movement",
        severity="high",
        description="Step up blocks or climb walls",
        class_patterns=[
            "Step.class", "Spider.class", "WallClimb.class",
            "StepModule.class", "HighJump.class",
        ],
        string_patterns=[
            "stepHeight", "stepValue", "spiderClimb", "wallClimb",
            "stepBypass", "stepPacket", "autoStep",
        ],
        package_patterns=[
            "module/movement/Step", "module/movement/Spider",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Jesus / WaterWalk",
        category="Movement",
        severity="high",
        description="Walk on water/lava",
        class_patterns=[
            "Jesus.class", "WaterWalk.class", "LiquidWalk.class",
            "JesusModule.class",
        ],
        string_patterns=[
            "jesusMode", "waterWalk", "liquidWalk", "walkOnWater",
            "jesusSpeed", "jesusPacket",
        ],
        package_patterns=[
            "module/movement/Jesus", "module/movement/WaterWalk",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="ElytraFly / ElytraBoost",
        category="Movement",
        severity="high",
        description="Enhanced elytra flight",
        class_patterns=[
            "ElytraFly.class", "ElytraBoost.class", "ElytraFlight.class",
            "ElytraPlus.class",
        ],
        string_patterns=[
            "elytraFly", "elytraBoost", "elytraSpeed", "elytraGlide",
            "elytraBypass", "fireworkBoost", "elytraPitch",
        ],
        package_patterns=[
            "module/movement/ElytraFly", "module/movement/ElytraFlight",
        ],
        min_matches=2,
    ),

    # ---- RENDER / VISUAL CHEATS ----
    CheatSignature(
        name="ESP / Tracers",
        category="Visual",
        severity="high",
        description="Renders player/entity outlines or tracer lines",
        class_patterns=[
            "ESP.class", "Tracers.class", "PlayerESP.class",
            "EntityESP.class", "BoxESP.class", "StorageESP.class",
        ],
        string_patterns=[
            "espMode", "tracerLine", "espBox", "espColor", "playerEsp",
            "entityEsp", "storageEsp", "espRange", "tracerWidth",
            "glowEsp", "outlineEsp", "chestEsp",
        ],
        package_patterns=[
            "module/render/ESP", "module/render/Tracers",
            "module/visual/ESP",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Xray",
        category="Visual",
        severity="critical",
        description="See through blocks to find ores/caves",
        class_patterns=[
            "Xray.class", "XRay.class", "OreESP.class",
            "XrayModule.class", "BlockXray.class",
        ],
        string_patterns=[
            "xrayMode", "xrayBlocks", "oreHighlight", "xrayOpacity",
            "xrayBrightness", "showOres", "xrayToggle", "blockFilter",
        ],
        package_patterns=[
            "module/render/Xray", "module/render/XRay",
            "module/visual/Xray",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Nametags / Enhanced Nametags",
        category="Visual",
        severity="medium",
        description="Shows extra info on player nametags (health, items)",
        class_patterns=[
            "Nametags.class", "BetterNametags.class",
            "NametagsModule.class", "CustomNametags.class",
        ],
        string_patterns=[
            "nametagHealth", "nametagArmor", "nametagItems",
            "nametagDistance", "customNametags", "nametagScale",
        ],
        package_patterns=[
            "module/render/Nametags", "module/visual/Nametags",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Fullbright / Gamma",
        category="Visual",
        severity="medium",
        description="Maximum brightness in dark areas",
        class_patterns=[
            "Fullbright.class", "Brightness.class", "GammaHack.class",
            "NightVision.class", "FullbrightModule.class",
        ],
        string_patterns=[
            "fullbright", "gammaValue", "maxBrightness", "nightVisionHack",
            "fullbrightMode", "gammaOverride",
        ],
        package_patterns=[
            "module/render/Fullbright", "module/visual/Fullbright",
        ],
        min_matches=2,
    ),

    # ---- KNOWN CHEAT CLIENTS ----
    CheatSignature(
        name="Meteor Client",
        category="Cheat Client",
        severity="critical",
        description="Meteor Client - popular Fabric cheat client",
        class_patterns=[
            "MeteorClient.class", "MeteorAddon.class",
        ],
        string_patterns=[
            "meteorclient", "meteor-client", "meteor.client",
            "meteordevelopment", "minegame159",
        ],
        package_patterns=[
            "meteordevelopment/meteorclient", "meteorclient/systems",
            "meteorclient/modules", "meteorclient/events",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Wurst Client",
        category="Cheat Client",
        severity="critical",
        description="Wurst Client - well-known cheat client",
        class_patterns=[
            "WurstClient.class", "WurstInitializer.class",
        ],
        string_patterns=[
            "wurstclient", "wurst-client", "wurst.client",
            "Alexander01998", "WurstHack",
        ],
        package_patterns=[
            "net/wurstclient", "wurstclient/hacks",
            "wurstclient/features", "wurstclient/events",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Future Client",
        category="Cheat Client",
        severity="critical",
        description="Future Client - premium cheat client",
        class_patterns=[
            "FutureClient.class",
        ],
        string_patterns=[
            "futureclient", "future-client", "future.client",
        ],
        package_patterns=[
            "com/futureclient", "futureclient/module",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Impact Client",
        category="Cheat Client",
        severity="critical",
        description="Impact Client - Minecraft cheat client",
        class_patterns=[
            "ImpactClient.class", "ImpactInstaller.class",
        ],
        string_patterns=[
            "impactclient", "impact-client", "impactdevelopment",
        ],
        package_patterns=[
            "impactclient/module", "impactdevelopment/client",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Aristois Client",
        category="Cheat Client",
        severity="critical",
        description="Aristois - modular cheat client",
        class_patterns=[
            "Aristois.class", "AristoisMod.class",
        ],
        string_patterns=[
            "aristois", "aristois.com",
        ],
        package_patterns=[
            "me/aristois", "aristois/module",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Inertia Client",
        category="Cheat Client",
        severity="critical",
        description="Inertia - Fabric cheat client",
        class_patterns=[
            "InertiaClient.class",
        ],
        string_patterns=[
            "inertiaclient", "inertia-client",
        ],
        package_patterns=[
            "inertiaclient/module", "inertiaclient/hack",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Lambda Client / LambdaHack",
        category="Cheat Client",
        severity="critical",
        description="Lambda - Kotlin-based cheat client",
        class_patterns=[
            "LambdaClient.class", "LambdaMod.class",
        ],
        string_patterns=[
            "lambdaclient", "lambda-client", "lambdahack",
        ],
        package_patterns=[
            "com/lambda", "lambdaclient/module",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Kami Blue",
        category="Cheat Client",
        severity="critical",
        description="KAMI Blue - anarchy cheat client",
        class_patterns=[
            "KamiBlue.class", "KamiBlueMod.class",
        ],
        string_patterns=[
            "kamiblue", "kami-blue", "kami.blue",
        ],
        package_patterns=[
            "org/kamiblue", "kamiblue/module",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Phobos Client",
        category="Cheat Client",
        severity="critical",
        description="Phobos - crystal PvP cheat client",
        class_patterns=[
            "Phobos.class", "PhobosClient.class",
        ],
        string_patterns=[
            "phobosclient", "phobos-client",
        ],
        package_patterns=[
            "me/earth2me/phobos", "phobos/module",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Konas Client",
        category="Cheat Client",
        severity="critical",
        description="Konas - premium crystal PvP client",
        class_patterns=[
            "Konas.class", "KonasClient.class",
        ],
        string_patterns=[
            "konasclient", "konas-client", "konas.client",
        ],
        package_patterns=[
            "me/konas", "konas/module",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="GameSense / GS Client",
        category="Cheat Client",
        severity="critical",
        description="GameSense - anarchy / crystal PvP client",
        class_patterns=[
            "GameSense.class", "GameSenseClient.class",
        ],
        string_patterns=[
            "gamesenseclient", "gamesense-client",
        ],
        package_patterns=[
            "com/gamesense", "gamesense/module",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="3arthh4ck / EarthHack",
        category="Cheat Client",
        severity="critical",
        description="3arthh4ck - anarchy PvP client",
        class_patterns=[
            "Earthhack.class", "EarthHack.class",
        ],
        string_patterns=[
            "3arthh4ck", "earthhack", "earth-hack",
        ],
        package_patterns=[
            "me/earth2me/earthhack", "earthhack/module",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Salhack",
        category="Cheat Client",
        severity="critical",
        description="Salhack - Forge/Fabric cheat client",
        class_patterns=[
            "Salhack.class", "SalhackMod.class",
        ],
        string_patterns=[
            "salhack", "sal-hack",
        ],
        package_patterns=[
            "me/ionar2/salhack", "salhack/module",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="ForgeHax",
        category="Cheat Client",
        severity="critical",
        description="ForgeHax - Forge-based cheat client",
        class_patterns=[
            "ForgeHax.class", "ForgeHaxMod.class",
        ],
        string_patterns=[
            "forgehax", "forge-hax",
        ],
        package_patterns=[
            "com/matt/forgehax", "forgehax/helper",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="BleachHack",
        category="Cheat Client",
        severity="critical",
        description="BleachHack - Fabric cheat client",
        class_patterns=[
            "BleachHack.class", "BleachHackMod.class",
        ],
        string_patterns=[
            "bleachhack", "bleach-hack", "BleachHack",
        ],
        package_patterns=[
            "org/bleachhack", "bleachhack/module",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Rusherhack",
        category="Cheat Client",
        severity="critical",
        description="RusherHack - premium anarchy client",
        class_patterns=[
            "RusherHack.class", "RusherHackClient.class",
        ],
        string_patterns=[
            "rusherhack", "rusher-hack", "rusherhackclient",
        ],
        package_patterns=[
            "org/rusherhack", "rusherhack/client",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="ThunderHack",
        category="Cheat Client",
        severity="critical",
        description="ThunderHack - Fabric cheat client",
        class_patterns=[
            "ThunderHack.class", "Thunderhack.class",
        ],
        string_patterns=[
            "thunderhack", "thunder-hack", "thunderhackrework",
        ],
        package_patterns=[
            "thunderhack/module", "thunderhack/feature",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="CoffeeClient",
        category="Cheat Client",
        severity="critical",
        description="Coffee Client - Fabric cheat client",
        class_patterns=[
            "CoffeeClient.class", "CoffeeMain.class",
        ],
        string_patterns=[
            "coffeeclient", "coffee-client",
        ],
        package_patterns=[
            "coffee/client", "coffeeclient/module",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Cornos Client",
        category="Cheat Client",
        severity="critical",
        description="Cornos - cheat client",
        class_patterns=[
            "Cornos.class", "CornosClient.class",
        ],
        string_patterns=[
            "cornoclient", "cornos",
        ],
        package_patterns=[
            "cornos/module",
        ],
        min_matches=2,
    ),

    # ---- MACRO TOOLS ----
    CheatSignature(
        name="198Macro",
        category="Macro Tool",
        severity="critical",
        description="198Macro - crystal PvP macro tool",
        class_patterns=[],
        string_patterns=[
            "198macro", "198_macro", "198 macro", "198macro.exe",
        ],
        file_patterns=[
            "198macro", "198Macro.exe", "198Macro.jar",
        ],
        min_matches=1,
    ),
    CheatSignature(
        name="ZenithMacro",
        category="Macro Tool",
        severity="critical",
        description="Zenith Macro - PvP macro tool",
        class_patterns=[],
        string_patterns=[
            "zenithmacro", "zenith_macro", "zenith macro", "zenithmacro.exe",
        ],
        file_patterns=[
            "zenithmacro", "ZenithMacro.exe", "ZenithMacro.jar",
        ],
        min_matches=1,
    ),
    CheatSignature(
        name="Crystal Macro (Generic)",
        category="Macro Tool",
        severity="high",
        description="Generic crystal PvP macro",
        class_patterns=[],
        string_patterns=[
            "crystalmacro", "crystal_macro", "cpvpmacro", "crystalpvpmacro",
            "anchorbot", "crystalbot",
        ],
        file_patterns=[
            "crystalmacro", "CrystalMacro",
        ],
        min_matches=2,
    ),

    # ---- GUI / MODULE SYSTEM PATTERNS ----
    CheatSignature(
        name="ClickGUI Module System",
        category="Cheat Framework",
        severity="critical",
        description="Cheat client module/GUI system detected",
        class_patterns=[
            "ClickGUI.class", "ClickGuiModule.class", "HudEditor.class",
            "ModuleManager.class", "HackManager.class",
        ],
        string_patterns=[
            "clickGUI", "clickGui", "click_gui", "moduleManager",
            "hackManager", "cheatManager", "moduleCategory",
            "enabledModules", "toggleModule", "hackList",
        ],
        package_patterns=[
            "module/client/ClickGUI", "gui/clickgui",
            "client/clickgui", "gui/hud/HudEditor",
        ],
        min_matches=3,  # Higher threshold to avoid false flags
    ),
    CheatSignature(
        name="BooleanSetting / Module System",
        category="Cheat Framework",
        severity="high",
        description="Cheat client settings system",
        class_patterns=[
            "BooleanSetting.class", "ModeSetting.class", "NumberSetting.class",
            "BindSetting.class", "ColorSetting.class",
        ],
        string_patterns=[
            "booleansetting", "BooleanSetting", "ModeSetting",
            "NumberSetting", "SliderSetting", "BindSetting",
        ],
        package_patterns=[
            "setting/BooleanSetting", "settings/BooleanSetting",
            "module/setting",
        ],
        min_matches=3,  # Need multiple settings classes
    ),

    # ---- PLAYER HACKS ----
    CheatSignature(
        name="Scaffold / AutoBridge",
        category="Player",
        severity="critical",
        description="Automatically places blocks while walking",
        class_patterns=[
            "Scaffold.class", "AutoBridge.class", "ScaffoldWalk.class",
            "BlockFly.class", "ScaffoldModule.class",
        ],
        string_patterns=[
            "scaffold", "autobridge", "scaffoldWalk", "blockFly",
            "scaffoldDelay", "scaffoldRotation", "towerMode",
            "scaffoldSwing", "scaffoldTower",
        ],
        package_patterns=[
            "module/player/Scaffold", "module/movement/Scaffold",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Nuker / AutoMine",
        category="Player",
        severity="critical",
        description="Automatically breaks blocks in range",
        class_patterns=[
            "Nuker.class", "AutoMine.class", "PacketMine.class",
            "InstantMine.class", "SpeedMine.class",
        ],
        string_patterns=[
            "nukerMode", "autoMine", "packetMine", "instantMine",
            "speedMine", "breakRange", "mineDelay", "nukerRange",
        ],
        package_patterns=[
            "module/player/Nuker", "module/player/AutoMine",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Baritone (as hidden mod)",
        category="Player",
        severity="medium",
        description="Baritone pathfinding AI (may indicate automation)",
        class_patterns=[
            "BaritoneAPI.class", "Baritone.class",
        ],
        string_patterns=[
            "baritone", "baritoneapi",
        ],
        package_patterns=[
            "baritone/api", "baritone/process",
        ],
        min_matches=3,  # High threshold - Baritone can be legit
    ),
    CheatSignature(
        name="AutoArmor",
        category="Player",
        severity="high",
        description="Automatically equips best armor",
        class_patterns=[
            "AutoArmor.class", "ArmorManager.class",
        ],
        string_patterns=[
            "autoarmor", "auto_armor", "armorSwitch", "bestArmor",
        ],
        package_patterns=[
            "module/player/AutoArmor",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="ChestStealer / AutoSteal",
        category="Player",
        severity="high",
        description="Automatically steals items from containers",
        class_patterns=[
            "ChestStealer.class", "AutoSteal.class", "Stealer.class",
        ],
        string_patterns=[
            "cheststealer", "autosteal", "stealDelay", "autoLoot",
        ],
        package_patterns=[
            "module/player/ChestStealer", "module/player/AutoSteal",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Timer Hack",
        category="Player",
        severity="critical",
        description="Modifies game tick speed",
        class_patterns=[
            "Timer.class", "TimerHack.class", "GameSpeed.class",
        ],
        string_patterns=[
            "timerSpeed", "timerValue", "timerMultiplier", "gameSpeed",
            "tickSpeed", "timerBypass",
        ],
        package_patterns=[
            "module/player/Timer", "module/misc/Timer",
        ],
        min_matches=2,
    ),

    # ---- WORLD CHEATS ----
    CheatSignature(
        name="Freecam (Cheat Version)",
        category="World",
        severity="medium",
        description="Camera detaches from player body",
        class_patterns=[
            "Freecam.class", "FreecamModule.class",
        ],
        string_patterns=[
            "freecamSpeed", "freecamClip", "freecamToggle",
        ],
        package_patterns=[
            "module/render/Freecam", "module/movement/Freecam",
        ],
        min_matches=2,  # Higher - freecam can be legit mod
    ),

    # ---- NETWORK / EXPLOIT ----
    CheatSignature(
        name="PacketFly",
        category="Network",
        severity="critical",
        description="Flying using packet manipulation",
        class_patterns=[
            "PacketFly.class", "PacketFlyModule.class",
        ],
        string_patterns=[
            "packetFly", "packetflight", "packetFlySpeed",
            "packetFlyMode", "flyPacket",
        ],
        package_patterns=[
            "module/movement/PacketFly",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Blink / FakeLag",
        category="Network",
        severity="high",
        description="Holds packets to create fake lag",
        class_patterns=[
            "Blink.class", "FakeLag.class", "PingSpoof.class",
        ],
        string_patterns=[
            "blinkMode", "fakeLag", "pingSpoof", "packetCancel",
            "blinkDelay", "lagTime",
        ],
        package_patterns=[
            "module/network/Blink", "module/misc/FakeLag",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Disabler / AntiCheat Bypass",
        category="Network",
        severity="critical",
        description="Attempts to disable server-side anticheat",
        class_patterns=[
            "Disabler.class", "AntiCheatBypass.class", "ACBypass.class",
        ],
        string_patterns=[
            "disabler", "anticheatBypass", "acBypass", "watchdogBypass",
            "sentinelBypass", "vulcanBypass", "nocomBypass",
        ],
        package_patterns=[
            "module/misc/Disabler", "module/exploit/Disabler",
        ],
        min_matches=2,
    ),

    # ---- INJECTION TOOLS ----
    CheatSignature(
        name="DLL Injector",
        category="Injection",
        severity="critical",
        description="DLL injection tool detected",
        class_patterns=[],
        string_patterns=[
            "dllinjector", "dll_injector", "injectdll", "inject.dll",
            "loadlibrary", "createremotethread",
        ],
        file_patterns=[
            "injector.exe", "inject.exe", "dllinjector",
        ],
        min_matches=1,
    ),
    CheatSignature(
        name="Process Hacker",
        category="Injection",
        severity="critical",
        description="Process Hacker can be used for DLL injection",
        class_patterns=[],
        string_patterns=[
            "processhacker", "process hacker", "ProcessHacker.exe",
            "processhacker2", "SystemInformer",
        ],
        file_patterns=[
            "ProcessHacker.exe", "SystemInformer.exe",
        ],
        min_matches=1,
    ),

    # ---- MORE CHEAT CLIENTS ----
    CheatSignature(
        name="LiquidBounce",
        category="Cheat Client",
        severity="critical",
        description="LiquidBounce - open source cheat client",
        class_patterns=[
            "LiquidBounce.class",
        ],
        string_patterns=[
            "liquidbounce", "liquid-bounce", "LiquidBounce",
        ],
        package_patterns=[
            "net/ccbluex/liquidbounce", "liquidbounce/features",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Azura Client",
        category="Cheat Client",
        severity="critical",
        description="Azura - cheat client",
        class_patterns=[
            "AzuraClient.class",
        ],
        string_patterns=[
            "azuraclient", "azura-client",
        ],
        package_patterns=[
            "azura/client",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Abyss Client",
        category="Cheat Client",
        severity="critical",
        description="Abyss Client",
        class_patterns=[
            "AbyssClient.class",
        ],
        string_patterns=[
            "abyssclient", "abyss-client",
        ],
        package_patterns=[
            "abyss/client",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Matix Client",
        category="Cheat Client",
        severity="critical",
        description="Matix Client",
        class_patterns=[],
        string_patterns=[
            "matixclient", "matix-client",
        ],
        package_patterns=[
            "matix/client",
        ],
        min_matches=2,
    ),
    CheatSignature(
        name="Sigma Client",
        category="Cheat Client",
        severity="critical",
        description="Sigma - premium cheat client",
        class_patterns=[
            "SigmaClient.class",
        ],
        string_patterns=[
            "sigmaclient", "sigma-client", "sigma5",
        ],
        package_patterns=[
            "info/sigmaclient",
        ],
        min_matches=2,
    ),
]


def is_whitelisted(filename: str) -> bool:
    """Check if a mod file is whitelisted (legitimate)."""
    name_lower = filename.lower().replace(" ", "").replace("-", "").replace("_", "")
    for wl in WHITELISTED_MODS:
        clean = wl.replace("-", "").replace("_", "")
        if clean in name_lower:
            return True
    return False


def scan_strings(content: str, signature: CheatSignature) -> List[str]:
    """Scan string content against a cheat signature."""
    matches = []
    content_lower = content.lower()

    for pattern in signature.string_patterns:
        if pattern.lower() in content_lower:
            matches.append(f"string:{pattern}")

    for pattern in signature.class_patterns:
        if pattern.lower() in content_lower:
            matches.append(f"class:{pattern}")

    for pattern in signature.package_patterns:
        if pattern.lower().replace("/", ".") in content_lower.replace("/", "."):
            matches.append(f"package:{pattern}")

    return matches


def scan_file_name(filename: str, signature: CheatSignature) -> List[str]:
    """Scan filename against cheat signature file patterns."""
    matches = []
    name_lower = filename.lower()

    for pattern in signature.file_patterns:
        if pattern.lower() in name_lower:
            matches.append(f"filename:{pattern}")

    for pattern in signature.string_patterns:
        if pattern.lower() in name_lower:
            matches.append(f"name_match:{pattern}")

    return matches


def detect_cheats(content: str, filename: str = "",
                  file_path: str = "") -> List[DetectionResult]:
    """
    Run all cheat signatures against content.
    Returns list of DetectionResult for any matches.
    """
    results = []

    # Skip whitelisted mods entirely
    if filename and is_whitelisted(filename):
        return results

    for sig in CHEAT_SIGNATURES:
        matched = []

        # String content scan
        if content:
            matched.extend(scan_strings(content, sig))

        # File name scan
        if filename:
            matched.extend(scan_file_name(filename, sig))

        # Only flag if we meet the minimum match threshold
        if len(matched) >= sig.min_matches:
            confidence = min(1.0, len(matched) / (sig.min_matches * 3))
            results.append(DetectionResult(
                flagged=True,
                signature_name=sig.name,
                category=sig.category,
                severity=sig.severity,
                description=sig.description,
                matched_patterns=matched,
                match_count=len(matched),
                file_path=file_path,
                confidence=round(confidence, 2),
            ))

    return results


def get_all_signatures() -> List[Dict]:
    """Return all signatures as dicts for API."""
    return [
        {
            "name": s.name,
            "category": s.category,
            "severity": s.severity,
            "description": s.description,
            "pattern_count": len(s.string_patterns) + len(s.class_patterns) + len(s.package_patterns),
        }
        for s in CHEAT_SIGNATURES
    ]
