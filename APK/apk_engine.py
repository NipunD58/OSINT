"""
APK Analysis Engine — Deep static analysis without external APIs.
Uses androguard for parsing + built-in threat intelligence databases.
"""

import hashlib
import zipfile
import re
import struct
import datetime
from pathlib import Path
from typing import Any
import traceback

# ── Androguard imports ────────────────────────────────────────────────────────
try:
    from androguard.misc import AnalyzeAPK
    from androguard.core.apk import APK
    ANDROGUARD_OK = True
except ImportError:
    ANDROGUARD_OK = False


# ═══════════════════════════════════════════════════════════════════════════════
# BUILT-IN THREAT INTELLIGENCE  (no API — embedded knowledge base)
# ═══════════════════════════════════════════════════════════════════════════════

# Dangerous permission combinations that appear in known malware families
MALWARE_PERMISSION_COMBOS = [
    {
        "combo": ["android.permission.READ_SMS", "android.permission.SEND_SMS",
                  "android.permission.RECEIVE_SMS"],
        "name": "SMS Stealer / Banking Trojan",
        "severity": "CRITICAL",
        "families": ["FluBot", "Joker", "TangleBot", "TeaBot"],
        "cve": "CVE-2021-0325",
        "description": "Full SMS interception and exfiltration — used to steal OTPs and banking codes."
    },
    {
        "combo": ["android.permission.RECORD_AUDIO", "android.permission.CAMERA",
                  "android.permission.ACCESS_FINE_LOCATION"],
        "name": "Stalkerware / Spyware",
        "severity": "CRITICAL",
        "families": ["Pegasus", "FinFisher", "Dendroid"],
        "cve": "CVE-2023-0266",
        "description": "Enables covert audio/video recording combined with precise location tracking."
    },
    {
        "combo": ["android.permission.BIND_ACCESSIBILITY_SERVICE",
                  "android.permission.SYSTEM_ALERT_WINDOW"],
        "name": "Overlay Attack / Clickjacking",
        "severity": "CRITICAL",
        "families": ["Anubis", "Cerberus", "SharkBot"],
        "cve": "CVE-2017-13274",
        "description": "Draws invisible overlays over banking/credential apps to steal inputs."
    },
    {
        "combo": ["android.permission.RECEIVE_BOOT_COMPLETED",
                  "android.permission.FOREGROUND_SERVICE"],
        "name": "Persistence Mechanism",
        "severity": "HIGH",
        "families": ["Generic Backdoor", "Ztorg"],
        "cve": None,
        "description": "Survives reboots and runs silently in foreground — common persistence trick."
    },
    {
        "combo": ["android.permission.READ_CONTACTS",
                  "android.permission.INTERNET",
                  "android.permission.READ_CALL_LOG"],
        "name": "Contact & Call Exfiltration",
        "severity": "HIGH",
        "families": ["Joker", "Agent Smith"],
        "cve": None,
        "description": "Harvests contacts and call history for spam/phishing campaigns."
    },
    {
        "combo": ["android.permission.INSTALL_PACKAGES",
                  "android.permission.REQUEST_INSTALL_PACKAGES"],
        "name": "Dropper / Installer",
        "severity": "HIGH",
        "families": ["Triada", "Ztorg", "xHelper"],
        "cve": "CVE-2019-2215",
        "description": "Can silently install additional APKs without user awareness."
    },
    {
        "combo": ["android.permission.WRITE_EXTERNAL_STORAGE",
                  "android.permission.READ_EXTERNAL_STORAGE",
                  "android.permission.MANAGE_EXTERNAL_STORAGE"],
        "name": "File Ransomware Risk",
        "severity": "HIGH",
        "families": ["Filecoder", "CryCryptor"],
        "cve": None,
        "description": "Broad file-system access — used by ransomware to encrypt user files."
    },
    {
        "combo": ["android.permission.CHANGE_NETWORK_STATE",
                  "android.permission.CHANGE_WIFI_STATE",
                  "android.permission.ACCESS_WIFI_STATE"],
        "name": "Network Manipulation",
        "severity": "MEDIUM",
        "families": ["Ghost Push", "Gooligan"],
        "cve": None,
        "description": "Can silently change Wi-Fi/network settings to redirect traffic."
    },
]

# Individual high-risk permissions
HIGH_RISK_PERMISSIONS = {
    "android.permission.BIND_DEVICE_ADMIN": {
        "risk": "CRITICAL", "reason": "Device administrator — can lock, wipe, or change lock screen"},
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "risk": "CRITICAL", "reason": "Can read/interact with any on-screen content"},
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "risk": "HIGH", "reason": "Draws overlays over other apps — used in overlay attacks"},
    "android.permission.READ_SMS": {
        "risk": "HIGH", "reason": "Access to all SMS messages including OTPs"},
    "android.permission.SEND_SMS": {
        "risk": "HIGH", "reason": "Can send SMS without user knowledge (premium SMS fraud)"},
    "android.permission.RECEIVE_SMS": {
        "risk": "HIGH", "reason": "Intercepts incoming SMS before user sees them"},
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "risk": "HIGH", "reason": "Intercepts outgoing calls — used for call hijacking"},
    "android.permission.RECORD_AUDIO": {
        "risk": "HIGH", "reason": "Microphone access — potential covert recording"},
    "android.permission.INSTALL_PACKAGES": {
        "risk": "HIGH", "reason": "Can install arbitrary APKs — dropper behaviour"},
    "android.permission.DELETE_PACKAGES": {
        "risk": "HIGH", "reason": "Can silently uninstall apps"},
    "android.permission.READ_CALL_LOG": {
        "risk": "HIGH", "reason": "Access to full call history"},
    "android.permission.WRITE_CALL_LOG": {
        "risk": "HIGH", "reason": "Can forge/delete call log entries"},
    "android.permission.GET_ACCOUNTS": {
        "risk": "MEDIUM", "reason": "Enumerates all Google/sync accounts on device"},
    "android.permission.USE_CREDENTIALS": {
        "risk": "HIGH", "reason": "Access to account credentials"},
    "android.permission.MANAGE_ACCOUNTS": {
        "risk": "HIGH", "reason": "Can add/remove/modify accounts"},
    "android.permission.NFC": {
        "risk": "MEDIUM", "reason": "NFC access — used in payment relay attacks"},
    "android.permission.BLUETOOTH_ADMIN": {
        "risk": "MEDIUM", "reason": "Can control Bluetooth — proximity tracking risk"},
    "android.permission.CHANGE_CONFIGURATION": {
        "risk": "MEDIUM", "reason": "Can change locale/display settings — locale bypass attacks"},
    "android.permission.REORDER_TASKS": {
        "risk": "MEDIUM", "reason": "Can move apps to foreground — task hijacking"},
    "android.permission.KILL_BACKGROUND_PROCESSES": {
        "risk": "MEDIUM", "reason": "Can terminate security/antivirus apps"},
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "risk": "MEDIUM", "reason": "Auto-starts on boot — persistence mechanism"},
    "android.permission.FOREGROUND_SERVICE": {
        "risk": "LOW", "reason": "Can run persistent foreground service"},
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "risk": "HIGH", "reason": "Can trigger APK installation prompts"},
    "android.permission.WRITE_SETTINGS": {
        "risk": "HIGH", "reason": "Can modify system settings silently"},
    "android.permission.CHANGE_NETWORK_STATE": {
        "risk": "MEDIUM", "reason": "Network manipulation capability"},
}

# Suspicious string patterns found in known malware
SUSPICIOUS_STRINGS = [
    # C2 / RAT patterns
    (r"(?:connectBack|reverse_shell|c2_server|command_and_control)", "CRITICAL", "Remote Access / C2 communication pattern"),
    (r"(?:su\b|root_shell|/system/bin/sh)", "CRITICAL", "Root/shell escalation attempt"),
    (r"(?:cipher\.getInstance\(['\"]DES['\"]|RC4|AES/ECB)", "HIGH", "Weak/known-bad encryption mode"),
    # Exfiltration
    (r"(?:getDeviceId|getImei|getImsi|getSimSerialNumber)", "HIGH", "Device identifier harvesting (IMEI/IMSI)"),
    (r"(?:getInstalledPackages|getInstalledApplications)", "MEDIUM", "App enumeration — fingerprinting device"),
    # Dynamic loading
    (r"(?:DexClassLoader|PathClassLoader|loadDex|BaseDexClassLoader)", "HIGH", "Dynamic code loading — evasion technique"),
    (r"(?:java\.lang\.Runtime.*exec|ProcessBuilder)", "HIGH", "Shell command execution"),
    (r"(?:reflection.*getDeclaredMethod|invoke\(null)", "MEDIUM", "Heavy reflection use — obfuscation evasion"),
    # Anti-analysis
    (r"(?:isDebuggerConnected|Debug\.isDebuggerConnected)", "HIGH", "Anti-debugging detection"),
    (r"(?:getprop ro\.build\.tags.*test-keys|isEmulator)", "HIGH", "Emulator/sandbox detection"),
    (r"(?:fridaDetect|xposed|substrate)", "HIGH", "Anti-hooking / anti-instrumentation"),
    # Crypto-mining
    (r"(?:monero|xmrig|coinhive|stratum\+tcp)", "CRITICAL", "Cryptocurrency mining indicators"),
    # Ransomware
    (r"(?:AES.*encrypt.*file|encryptFile|lockScreen.*ransom)", "CRITICAL", "File encryption / ransomware pattern"),
    # Data theft
    (r"(?:clipboardManager|getClipboardText|setPrimaryClip)", "MEDIUM", "Clipboard access — credential theft risk"),
    (r"(?:KeyEvent\.KEYCODE|onKeyDown.*password)", "HIGH", "Keylogger pattern"),
    # Network
    (r"(?:\.onion|tor2web|torproject)", "HIGH", "Tor network communication — C2 anonymisation"),
    (r"(?:ngrok\.io|serveo\.net|pagekite)", "MEDIUM", "Tunneling service — C2 relay"),
]

# Known malicious package name patterns
MALICIOUS_PACKAGE_PATTERNS = [
    (r"^com\.android\.system\.", "System impersonation"),
    (r"^com\.google\.android\.(?!apps|gms|gsf|vending|provider)", "Google impersonation"),
    (r"update.*manager|system.*update|android.*update", "Fake update app"),
    (r"(?:flashlight|torch).*(?:pro|premium|free)", "Adware flashlight clone"),
    (r"com\.whatsapp\.[a-z]+", "WhatsApp clone/mod"),
    (r"^org\.telegram\.[a-z]+", "Telegram mod/clone"),
    (r"(?:banking|wallet|pay).*(?:secure|official|app)", "Fake banking app pattern"),
]

# Recent malware family signatures (hash patterns / package names from public reports)
KNOWN_MALWARE_FAMILIES = {
    "FluBot": {
        "description": "SMS-based banking trojan that steals credentials and spreads via SMS phishing",
        "permissions": ["READ_SMS", "SEND_SMS", "BIND_ACCESSIBILITY_SERVICE"],
        "min_match": 3,
        "severity": "CRITICAL",
        "source": "CERT-EU Advisory 2021-045",
    },
    "Joker": {
        "description": "Fleeceware subscribing victims to premium services silently",
        "permissions": ["READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "INTERNET"],
        "min_match": 3,
        "severity": "CRITICAL",
        "source": "Google Threat Analysis Group 2020",
    },
    "SharkBot": {
        "description": "Banking trojan using Accessibility Service for overlay and keylogging attacks",
        "permissions": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW",
                        "READ_SMS", "INTERNET"],
        "min_match": 3,
        "severity": "CRITICAL",
        "source": "NCC Group Report 2022",
    },
    "Cerberus": {
        "description": "MaaS banking trojan with RAT capabilities, sold on dark web forums",
        "permissions": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW",
                        "SEND_SMS", "READ_SMS", "RECORD_AUDIO"],
        "min_match": 4,
        "severity": "CRITICAL",
        "source": "ThreatFabric Report 2020",
    },
    "xHelper": {
        "description": "Persistent dropper that reinstalls itself after removal — rootkit-level persistence",
        "permissions": ["INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES",
                        "RECEIVE_BOOT_COMPLETED"],
        "min_match": 3,
        "severity": "CRITICAL",
        "source": "Symantec Threat Intelligence 2019",
    },
    "Anubis": {
        "description": "Banking trojan with keylogging, overlay attacks, and ransomware module",
        "permissions": ["BIND_ACCESSIBILITY_SERVICE", "RECORD_AUDIO",
                        "READ_SMS", "CAMERA"],
        "min_match": 3,
        "severity": "CRITICAL",
        "source": "ESET Threat Report 2021",
    },
    "TeaBot": {
        "description": "Banking trojan intercepting credentials via Accessibility Service",
        "permissions": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW",
                        "READ_SMS", "SEND_SMS"],
        "min_match": 3,
        "severity": "CRITICAL",
        "source": "Cleafy Mobile Threat Intelligence 2021",
    },
    "Triada": {
        "description": "Modular trojan pre-installed on devices — steals SMS and installs payloads",
        "permissions": ["INSTALL_PACKAGES", "READ_SMS", "INTERNET",
                        "RECEIVE_BOOT_COMPLETED"],
        "min_match": 3,
        "severity": "HIGH",
        "source": "Kaspersky Securelist 2019",
    },
}

# Suspicious native libraries
SUSPICIOUS_NATIVE_LIBS = {
    "libdvm.so": "Direct Dalvik VM manipulation — privilege escalation",
    "libmtk.so": "MediaTek root exploit loader",
    "libsupol.so": "SuperSU helper — rooting attempt",
    "libkingroot.so": "KingRoot exploit — known rooting tool",
    "libqsee.so": "QSEE/TrustZone manipulation — bootloader bypass",
}

SUSPICIOUS_ASSET_EXTENSIONS = {".dex", ".jar", ".so", ".bin", ".enc", ".dat"}


# ═══════════════════════════════════════════════════════════════════════════════
# CORE ANALYSIS FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def compute_hashes(apk_path: str) -> dict:
    """Compute MD5, SHA1, SHA256 of the APK file."""
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            for v in h.values():
                v.update(chunk)
    return {k: v.hexdigest() for k, v in h.items()}


def get_file_info(apk_path: str) -> dict:
    """Basic file metadata."""
    p = Path(apk_path)
    stat = p.stat()
    return {
        "filename": p.name,
        "size_bytes": stat.st_size,
        "size_mb": round(stat.st_size / 1_048_576, 2),
        "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
    }


def extract_zip_contents(apk_path: str) -> dict:
    """
    APKs are ZIP archives. Extract file listing, detect suspicious embedded files,
    and check for encrypted/obfuscated DEX payloads.
    """
    result = {
        "total_files": 0,
        "dex_files": [],
        "native_libs": [],
        "assets": [],
        "suspicious_files": [],
        "multi_dex": False,
        "has_native_code": False,
    }
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            names = z.namelist()
            result["total_files"] = len(names)
            for name in names:
                low = name.lower()
                if low.endswith(".dex"):
                    result["dex_files"].append(name)
                elif low.endswith(".so"):
                    result["native_libs"].append(name)
                    result["has_native_code"] = True
                    lib_name = Path(name).name
                    if lib_name in SUSPICIOUS_NATIVE_LIBS:
                        result["suspicious_files"].append({
                            "file": name,
                            "reason": SUSPICIOUS_NATIVE_LIBS[lib_name],
                            "severity": "HIGH"
                        })
                elif "/assets/" in name:
                    result["assets"].append(name)
                    suffix = Path(name).suffix.lower()
                    if suffix in SUSPICIOUS_ASSET_EXTENSIONS:
                        result["suspicious_files"].append({
                            "file": name,
                            "reason": f"Suspicious binary asset ({suffix}) — possible hidden payload",
                            "severity": "MEDIUM"
                        })
            result["multi_dex"] = len(result["dex_files"]) > 1
    except Exception as e:
        result["error"] = str(e)
    return result


def analyze_permissions(permissions: list) -> dict:
    """Deep permission analysis — identify risks, combos, malware patterns."""
    result = {
        "total": len(permissions),
        "dangerous": [],
        "normal": [],
        "signature": [],
        "unknown": [],
        "high_risk": [],
        "combo_matches": [],
    }

    perm_short = {p.split(".")[-1] for p in permissions}

    for p in permissions:
        short = p.split(".")[-1]
        if p in HIGH_RISK_PERMISSIONS:
            info = HIGH_RISK_PERMISSIONS[p]
            result["high_risk"].append({
                "permission": p,
                "short": short,
                "risk": info["risk"],
                "reason": info["reason"]
            })
        if "DANGEROUS" in p or p in HIGH_RISK_PERMISSIONS:
            result["dangerous"].append(p)
        elif "NORMAL" in p:
            result["normal"].append(p)
        else:
            result["unknown"].append(p)

    # Check malware permission combos
    for combo_def in MALWARE_PERMISSION_COMBOS:
        required = set(combo_def["combo"])
        matched = required.intersection(set(permissions))
        if len(matched) >= max(2, len(required) - 1):  # Allow one missing
            result["combo_matches"].append({
                **combo_def,
                "matched_permissions": list(matched),
                "match_score": f"{len(matched)}/{len(required)}"
            })

    return result


def scan_strings_in_apk(apk_path: str) -> list:
    """
    Scan all DEX files inside the APK for suspicious strings using raw binary search.
    This avoids needing full disassembly for speed.
    """
    findings = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            dex_files = [n for n in z.namelist() if n.endswith(".dex")]
            for dex_name in dex_files:
                data = z.read(dex_name).decode("latin-1")  # Raw bytes as latin-1
                for pattern, severity, description in SUSPICIOUS_STRINGS:
                    matches = re.findall(pattern, data, re.IGNORECASE)
                    if matches:
                        findings.append({
                            "pattern": pattern,
                            "severity": severity,
                            "description": description,
                            "found_in": dex_name,
                            "sample_matches": list(set(matches))[:3]
                        })
    except Exception as e:
        findings.append({"error": str(e)})
    return findings


def extract_certificate_info(apk) -> dict:
    """Extract signing certificate details for developer identification."""
    cert_info = {
        "certificates": [],
        "is_debug_signed": False,
        "is_self_signed": False,
        "developer_hints": []
    }
    try:
        certs = apk.get_certificates()
        for cert in certs:
            subject = {}
            try:
                for attr in cert.subject.chosen:
                    oid = attr["type"].dotted
                    val = str(attr["value"].chosen)
                    name_map = {
                        "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L",
                        "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
                        "1.2.840.113549.1.9.1": "Email",
                    }
                    key = name_map.get(oid, oid)
                    subject[key] = val
            except Exception:
                pass

            issuer = {}
            try:
                for attr in cert.issuer.chosen:
                    oid = attr["type"].dotted
                    val = str(attr["value"].chosen)
                    name_map = {
                        "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L",
                        "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
                    }
                    key = name_map.get(oid, oid)
                    issuer[key] = val
            except Exception:
                pass

            # Check for debug / self-signed
            is_self_signed = subject == issuer
            is_debug = any(
                kw in str(subject).lower()
                for kw in ["android debug", "androiddebugkey", "test key", "debug key"]
            )

            # Serial / validity
            try:
                not_before = str(cert["tbs_certificate"]["validity"]["not_before"].chosen.contents)
                not_after = str(cert["tbs_certificate"]["validity"]["not_after"].chosen.contents)
            except Exception:
                not_before = not_after = "Unknown"

            cert_dict = {
                "subject": subject,
                "issuer": issuer,
                "is_self_signed": is_self_signed,
                "is_debug": is_debug,
                "not_before": not_before,
                "not_after": not_after,
            }
            cert_info["certificates"].append(cert_dict)

            if is_debug:
                cert_info["is_debug_signed"] = True
                cert_info["developer_hints"].append("⚠️ Signed with Android debug key — NOT a production release")
            if is_self_signed:
                cert_info["is_self_signed"] = True
                cert_info["developer_hints"].append("Self-signed certificate — not verified by a CA")

            # Developer identification clues
            if subject.get("O"):
                cert_info["developer_hints"].append(f"Organisation: {subject['O']}")
            if subject.get("CN"):
                cert_info["developer_hints"].append(f"Common Name: {subject['CN']}")
            if subject.get("Email"):
                cert_info["developer_hints"].append(f"Email: {subject['Email']}")
            if subject.get("C"):
                cert_info["developer_hints"].append(f"Country: {subject['C']}")

    except Exception as e:
        cert_info["error"] = str(e)
    return cert_info


def extract_network_indicators(apk_path: str) -> dict:
    """Extract URLs, IPs, domains from all DEX and resource files."""
    indicators = {"urls": set(), "ips": set(), "domains": set(), "suspicious_domains": []}

    url_re = re.compile(r'https?://[^\s\'"<>]{5,150}', re.IGNORECASE)
    ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b')
    domain_re = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|top|xyz|online|site|club|info|biz|cc|to)\b', re.IGNORECASE)

    suspicious_tlds = {".tk", ".top", ".xyz", ".online", ".site", ".club", ".cc", ".to", ".ru", ".cn"}

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if any(name.endswith(ext) for ext in [".dex", ".xml", ".json", ".js", ".html"]):
                    try:
                        data = z.read(name).decode("latin-1")
                        for url in url_re.findall(data):
                            indicators["urls"].add(url[:200])
                        for ip in ip_re.findall(data):
                            # Filter out version numbers (1.0.0)
                            parts = ip.split(".")
                            if all(0 <= int(p.split(":")[0]) <= 255 for p in parts[:4]):
                                indicators["ips"].add(ip)
                        for d in domain_re.findall(data):
                            indicators["domains"].add(d)
                            if any(d.lower().endswith(tld) for tld in suspicious_tlds):
                                indicators["suspicious_domains"].append(d)
                    except Exception:
                        pass
    except Exception:
        pass

    indicators["urls"] = sorted(indicators["urls"])
    indicators["ips"] = sorted(indicators["ips"])
    indicators["domains"] = sorted(indicators["domains"])
    indicators["suspicious_domains"] = sorted(set(indicators["suspicious_domains"]))
    return indicators


def check_malware_family_similarity(permissions: list, string_findings: list) -> list:
    """Compare against known malware family profiles."""
    matches = []
    perm_set = set(p.split(".")[-1] for p in permissions)

    for family, profile in KNOWN_MALWARE_FAMILIES.items():
        required = set(profile["permissions"])
        matched = required.intersection(perm_set)
        score = len(matched) / len(required)
        if len(matched) >= profile["min_match"]:
            matches.append({
                "family": family,
                "description": profile["description"],
                "severity": profile["severity"],
                "match_score": round(score * 100),
                "matched_permissions": sorted(matched),
                "missing_permissions": sorted(required - matched),
                "source": profile["source"],
            })

    return sorted(matches, key=lambda x: x["match_score"], reverse=True)


def identify_developer(apk, cert_info: dict, package_name: str, network: dict) -> dict:
    """
    Best-effort developer identification using certificate, package name,
    metadata, and network indicators.
    """
    dev = {
        "package_name": package_name,
        "confidence": "LOW",
        "identity_clues": [],
        "store_links": [],
        "red_flags": [],
    }

    # From certificate
    for cert in cert_info.get("certificates", []):
        subj = cert.get("subject", {})
        if subj.get("O") and subj["O"].lower() not in ["unknown", "test", "android"]:
            dev["identity_clues"].append(("Organisation", subj["O"], "Certificate"))
            dev["confidence"] = "MEDIUM"
        if subj.get("CN") and subj["CN"].lower() not in ["android debug", "test"]:
            dev["identity_clues"].append(("Common Name", subj["CN"], "Certificate"))
        if subj.get("Email"):
            dev["identity_clues"].append(("Email", subj["Email"], "Certificate"))
            dev["confidence"] = "HIGH"
        if subj.get("L"):
            dev["identity_clues"].append(("City", subj["L"], "Certificate"))
        if subj.get("ST"):
            dev["identity_clues"].append(("State", subj["ST"], "Certificate"))
        if subj.get("C"):
            dev["identity_clues"].append(("Country", subj["C"], "Certificate"))

    # From package name
    parts = package_name.split(".")
    if len(parts) >= 2:
        inferred_domain = f"{parts[1]}.{parts[0]}" if len(parts[0]) <= 4 else f"{parts[0]}.{parts[1]}"
        dev["identity_clues"].append(("Inferred Domain", inferred_domain, "Package Name"))
        dev["store_links"].append(
            f"https://play.google.com/store/apps/details?id={package_name}")

    # From network indicators
    urls = network.get("urls", [])
    domains = [u.split("/")[2] for u in urls if "://" in u]
    for d in set(domains)[:5]:
        dev["identity_clues"].append(("Network Domain", d, "Embedded URL"))

    # Red flags
    for pattern, reason in MALICIOUS_PACKAGE_PATTERNS:
        if re.search(pattern, package_name, re.IGNORECASE):
            dev["red_flags"].append(reason)

    if cert_info.get("is_debug_signed"):
        dev["red_flags"].append("Debug-signed — never published on Play Store legitimately")
    if cert_info.get("is_self_signed"):
        dev["red_flags"].append("Self-signed certificate — unverified publisher")

    return dev


def calculate_risk_score(perm_analysis: dict, string_findings: list,
                         family_matches: list, zip_info: dict,
                         cert_info: dict, network: dict) -> dict:
    """
    Holistic risk score: 0–100 with breakdown.
    """
    score = 0
    breakdown = []

    # Permission risk (max 35 pts)
    critical_perms = sum(1 for p in perm_analysis["high_risk"] if p["risk"] == "CRITICAL")
    high_perms = sum(1 for p in perm_analysis["high_risk"] if p["risk"] == "HIGH")
    perm_pts = min(35, critical_perms * 10 + high_perms * 5)
    score += perm_pts
    breakdown.append(("Permission Risk", perm_pts, 35, f"{critical_perms} critical, {high_perms} high-risk permissions"))

    # Combo matches (max 20 pts)
    combo_severity = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4}
    combo_pts = min(20, sum(combo_severity.get(c["severity"], 2) for c in perm_analysis["combo_matches"]))
    score += combo_pts
    breakdown.append(("Dangerous Permission Combos", combo_pts, 20, f"{len(perm_analysis['combo_matches'])} dangerous combinations"))

    # String findings (max 20 pts)
    str_severity = {"CRITICAL": 8, "HIGH": 5, "MEDIUM": 2}
    str_pts = min(20, sum(str_severity.get(f.get("severity", "LOW"), 1) for f in string_findings if "error" not in f))
    score += str_pts
    breakdown.append(("Suspicious Code Patterns", str_pts, 20, f"{len(string_findings)} suspicious patterns found"))

    # Family similarity (max 15 pts)
    fam_pts = min(15, len(family_matches) * 8) if family_matches else 0
    score += fam_pts
    breakdown.append(("Malware Family Similarity", fam_pts, 15, f"{len(family_matches)} family matches"))

    # Structural anomalies (max 10 pts)
    struct_pts = 0
    if zip_info.get("multi_dex"):
        struct_pts += 3
    if len(zip_info.get("suspicious_files", [])) > 0:
        struct_pts += min(7, len(zip_info["suspicious_files"]) * 3)
    struct_pts = min(10, struct_pts)
    score += struct_pts
    breakdown.append(("Structural Anomalies", struct_pts, 10, "Multi-DEX, suspicious embedded files"))

    # Certificate issues (max 5 pts — less decisive)
    cert_pts = 0
    if cert_info.get("is_debug_signed"):
        cert_pts += 3
    if cert_info.get("is_self_signed"):
        cert_pts += 2
    score += cert_pts
    breakdown.append(("Certificate Issues", cert_pts, 5, "Debug/self-signed certificates"))

    # Network indicators (max 5 pts)
    net_pts = min(5, len(network.get("suspicious_domains", [])) * 2)
    score += net_pts
    breakdown.append(("Suspicious Network Indicators", net_pts, 5, f"{len(network.get('suspicious_domains', []))} suspicious domains"))

    score = min(100, score)

    if score >= 75:
        verdict = "MALICIOUS"
        color = "#ff4444"
    elif score >= 50:
        verdict = "SUSPICIOUS"
        color = "#ff8800"
    elif score >= 25:
        verdict = "POTENTIALLY UNWANTED"
        color = "#ffcc00"
    else:
        verdict = "LIKELY CLEAN"
        color = "#44bb44"

    return {
        "score": score,
        "verdict": verdict,
        "color": color,
        "breakdown": breakdown,
    }


def generate_recommendations(risk: dict, perm_analysis: dict,
                             family_matches: list, cert_info: dict) -> list:
    """Generate actionable recommendations."""
    recs = []

    if risk["verdict"] == "MALICIOUS":
        recs.append({"level": "CRITICAL", "action": "DO NOT install or run this APK. Delete it immediately."})
        recs.append({"level": "CRITICAL", "action": "If already installed, perform a factory reset and change all passwords from a clean device."})

    if risk["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
        recs.append({"level": "HIGH", "action": "Submit the APK hash to VirusTotal (virustotal.com) for multi-engine scanning."})
        recs.append({"level": "HIGH", "action": "Report to your national CERT or cybersecurity authority."})

    for match in family_matches:
        recs.append({"level": "HIGH", "action": f"Behaviour matches {match['family']} — review {match['source']} for IOCs."})

    if perm_analysis.get("combo_matches"):
        for combo in perm_analysis["combo_matches"]:
            if combo["severity"] == "CRITICAL":
                recs.append({"level": "HIGH", "action": f"Dangerous permission combo detected: {combo['name']}. Revoke permissions if installed."})

    if cert_info.get("is_debug_signed"):
        recs.append({"level": "MEDIUM", "action": "App is debug-signed — never from an official app store. Avoid sideloading."})

    if not recs:
        recs.append({"level": "INFO", "action": "No critical issues found. Continue monitoring and keep the device OS updated."})
        recs.append({"level": "INFO", "action": "Always install apps from trusted sources like Google Play Store."})

    return recs


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_apk(apk_path: str, progress_callback=None) -> dict:
    """
    Full APK analysis pipeline. Returns a structured report dict.
    progress_callback(step: int, total: int, message: str) for UI updates.
    """
    def progress(step, msg):
        if progress_callback:
            progress_callback(step, 10, msg)

    report = {"success": False, "error": None}

    try:
        progress(1, "Computing file hashes…")
        report["hashes"] = compute_hashes(apk_path)
        report["file_info"] = get_file_info(apk_path)

        progress(2, "Inspecting ZIP structure…")
        report["zip_contents"] = extract_zip_contents(apk_path)

        progress(3, "Scanning for suspicious strings…")
        report["string_findings"] = scan_strings_in_apk(apk_path)

        progress(4, "Extracting network indicators…")
        report["network"] = extract_network_indicators(apk_path)

        if not ANDROGUARD_OK:
            report["error"] = "androguard not available — install with: pip install androguard"
            report["success"] = False
            return report

        progress(5, "Parsing APK manifest…")
        apk_obj, _, _ = AnalyzeAPK(apk_path)

        progress(6, "Analysing permissions…")
        all_perms = list(apk_obj.get_permissions() or [])
        report["permissions"] = analyze_permissions(all_perms)
        report["permissions"]["all"] = all_perms

        progress(7, "Extracting certificate information…")
        report["certificate"] = extract_certificate_info(apk_obj)

        progress(8, "Checking malware family similarity…")
        report["family_matches"] = check_malware_family_similarity(
            all_perms, report["string_findings"])

        progress(9, "Identifying developer…")
        package = apk_obj.get_package() or "unknown"
        report["app_info"] = {
            "package_name": package,
            "app_name": apk_obj.get_app_name() or "Unknown",
            "version_name": apk_obj.get_androidversion_name() or "Unknown",
            "version_code": apk_obj.get_androidversion_code() or "Unknown",
            "min_sdk": apk_obj.get_min_sdk_version() or "Unknown",
            "target_sdk": apk_obj.get_target_sdk_version() or "Unknown",
            "main_activity": apk_obj.get_main_activity() or "None",
            "activities": list(apk_obj.get_activities() or []),
            "services": list(apk_obj.get_services() or []),
            "receivers": list(apk_obj.get_receivers() or []),
            "providers": list(apk_obj.get_providers() or []),
            "libraries": list(apk_obj.get_libraries() or []),
            "features": list(apk_obj.get_features() or []),
            "declared_intents": list(apk_obj.get_declared_permissions() or []),
        }
        report["developer"] = identify_developer(
            apk_obj, report["certificate"], package, report["network"])

        progress(10, "Calculating risk score…")
        report["risk"] = calculate_risk_score(
            report["permissions"], report["string_findings"],
            report["family_matches"], report["zip_contents"],
            report["certificate"], report["network"])

        report["recommendations"] = generate_recommendations(
            report["risk"], report["permissions"],
            report["family_matches"], report["certificate"])

        report["success"] = True
        report["analysis_timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"

    except Exception as e:
        report["error"] = str(e)
        report["traceback"] = traceback.format_exc()

    return report
