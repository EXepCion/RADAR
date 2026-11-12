"""Offline knowledge used for risk scoring: network (ASN) categories and attack-tool user agents.

Kept local on purpose: no sign-in data is sent to third-party lookup services.
Extend via settings (``extra_asns``, ``suspicious_user_agents``) without code changes.
"""
from __future__ import annotations

import re

# category -> points added to the risk score
ASN_CATEGORY_POINTS = {"bulletproof": 35, "hosting": 25, "vpn": 20, "cloud": 10}

# Well-known autonomous systems that are not residential/mobile/business ISPs.
KNOWN_ASNS: dict[int, tuple[str, str]] = {
    # commercial VPN / anonymizer networks
    9009: ("M247 (VPN providers)", "vpn"),
    60068: ("Datacamp / CDN77 (VPN providers)", "vpn"),
    212238: ("Datacamp (VPN providers)", "vpn"),
    136787: ("Tefincom (NordVPN)", "vpn"),
    39351: ("31173 Services (Mullvad VPN)", "vpn"),
    13335: ("Cloudflare (WARP / proxy)", "vpn"),
    # VPS / hosting (typical attacker and AiTM-phishing infrastructure)
    14061: ("DigitalOcean", "hosting"),
    16276: ("OVH", "hosting"),
    24940: ("Hetzner", "hosting"),
    20473: ("Vultr / Choopa", "hosting"),
    63949: ("Linode / Akamai Cloud", "hosting"),
    12876: ("Scaleway", "hosting"),
    51167: ("Contabo", "hosting"),
    60781: ("Leaseweb NL", "hosting"),
    28753: ("Leaseweb DE", "hosting"),
    30633: ("Leaseweb US", "hosting"),
    8560: ("IONOS", "hosting"),
    197540: ("netcup", "hosting"),
    62240: ("Clouvider", "hosting"),
    49981: ("WorldStream", "hosting"),
    36352: ("ColoCrossing", "hosting"),
    8100: ("QuadraNet", "hosting"),
    29802: ("Hivelocity", "hosting"),
    46562: ("Performive", "hosting"),
    63473: ("HostHatch", "hosting"),
    14956: ("RouterHosting / Cloudzy", "hosting"),
    22612: ("Namecheap", "hosting"),
    26496: ("GoDaddy", "hosting"),
    46606: ("Unified Layer", "hosting"),
    9123: ("TimeWeb", "hosting"),
    200019: ("AlexHost", "hosting"),
    216071: ("VDSINA", "hosting"),
    32613: ("iWeb", "hosting"),
    23470: ("ReliableSite", "hosting"),
    62904: ("Eonix", "hosting"),
    51852: ("Private Layer", "hosting"),
    47890: ("Unmanaged Ltd", "hosting"),
    209588: ("Flyservers", "hosting"),
    54825: ("Equinix Metal", "hosting"),
    # bulletproof / frequently abused hosters
    44477: ("Stark Industries", "bulletproof"),
    210644: ("AEZA Group", "bulletproof"),
    211252: ("Delis", "bulletproof"),
    202425: ("IP Volume", "bulletproof"),
    53667: ("FranTech / BuyVM", "bulletproof"),
    # hyperscale clouds (also legit: Windows 365 / AVD, SaaS integrations)
    8075: ("Microsoft / Azure", "cloud"),
    16509: ("Amazon AWS", "cloud"),
    14618: ("Amazon AWS", "cloud"),
    15169: ("Google", "cloud"),
    396982: ("Google Cloud", "cloud"),
    31898: ("Oracle Cloud", "cloud"),
    45102: ("Alibaba Cloud", "cloud"),
    37963: ("Alibaba Cloud", "cloud"),
    132203: ("Tencent Cloud", "cloud"),
    45090: ("Tencent Cloud", "cloud"),
}

# HTTP libraries / tools that a real user's browser or Office app never sends.
DEFAULT_SUSPICIOUS_USER_AGENTS = [
    r"python-requests", r"python-urllib", r"\baiohttp", r"\bhttpx\b", r"\baxios/", r"node-fetch", r"\bundici\b",
    r"go-http-client", r"\bfasthttp", r"^curl/", r"\blibcurl", r"^wget/", r"apache-httpclient", r"^java/",
    r"postmanruntime", r"headlesschrome", r"phantomjs", r"\bBAV2ROPC\b", r"\bscrapy\b", r"\bpowershell/",
    # seen in the password campaign against this tenant (never on a successful sign-in):
    r"^mozilla/5\.0$",  # bare
    r"^mozilla/5\.0 \(windows nt 10\.0; win64; x64\) applewebkit/537\.36$",  # truncated, no browser part
    r"^<[a-z_]+>$",  # unfilled template placeholder such as <RndUA>
]

# First-party clients used by admins - and by recon/attack tooling (AzureHound, ROADtools, GraphRunner ...).
SENSITIVE_APPS: dict[str, str] = {
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Microsoft Azure CLI",
    "1950a258-227b-4e31-a9cf-717495945fc2": "Microsoft Azure PowerShell",
    "14d82eec-204b-4c2f-b7e8-296a70dab67e": "Microsoft Graph Command Line Tools",
    "1b730954-1685-4b74-9bfd-dac224a7b894": "Azure Active Directory PowerShell",
    "de8bc8b5-d9f9-48b1-a8ad-b748da725064": "Graph Explorer",
    "fb78d390-0c51-40cd-8e17-fdbfab77341b": "Exchange Online PowerShell",
    "d1ddf0e4-d672-4dae-b554-9d5bdfd93547": "Microsoft Intune PowerShell",
}
DEVICE_REGISTRATION_RESOURCE = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"

# Tenants that own Microsoft first-party apps (appOwnerTenantId of the sign-in)
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}
# Microsoft back-end services known to sign in for users (also recognised in history stored before the
# appOwnerTenantId / clientCredentialType fields were kept)
MICROSOFT_BACKEND_APPS = {
    "bb893c22-978d-4cd4-a6f7-bb6cc0d6e6ce": "Olympus (Office policy service, resource OCaaS Client Interaction "
                                            "Service, scope UserPolicies.Read)",
}

PHISHING_RESISTANT_METHODS =("windows hello", "fido2", "passkey", "certificate", "x.509", "platform credential")
WEAK_MFA_METHODS = ("text message", "sms", "phone call", "voice")


# clientAppUsed values that Conditional Access treats as legacy authentication ("Unknown" is NOT one of them).
# Exchange logs these via ROPC with user agent "BAV2ROPC" - that is legacy auth, not an attack tool by itself.
LEGACY_CLIENT_APPS = {
    "authenticated smtp", "autodiscover", "exchange activesync", "exchange online powershell",
    "exchange web services", "imap4", "imap", "mapi over http", "offline address book", "other clients",
    "outlook anywhere (rpc over http)", "pop3", "pop", "reporting web services", "universal outlook",
}

# Keywords in the registered AS holder name (e.g. from RIPEstat) -> category, for networks not listed above.
NAME_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("vpn", ("vpn", "proxy", "onion", "tor exit", "torservers", "anonym", "mullvad", "nordvpn", "surfshark",
             "expressvpn", "protonvpn", "privacy")),
    ("hosting", ("hosting", "hoster", "server", "vps", "datacenter", "data center", "data-center", "colocation",
                 "dedicated", "cloud", "virtual machine", "compute")),
]


def classify_asn_name(name: str) -> str | None:
    lowered = f" {name.lower()} "
    for category, words in NAME_KEYWORDS:
        if any(w in lowered for w in words):
            return category
    return None


def asn_info(asn: int | None, extra: dict | None = None) -> tuple[str, str] | None:
    """(name, category) for a known non-ISP network, else None."""
    if not asn:
        return None
    if extra:
        hit = extra.get(str(asn)) or extra.get(asn)
        if hit:
            name, category = (hit if isinstance(hit, (list, tuple)) else (str(hit), "hosting"))[:2]
            return str(name), str(category)
    return KNOWN_ASNS.get(int(asn))


def compile_user_agents(patterns: list[str] | None) -> re.Pattern | None:
    items = [p for p in (patterns if patterns is not None else DEFAULT_SUSPICIOUS_USER_AGENTS) if p]
    return re.compile("|".join(f"(?:{p})" for p in items), re.IGNORECASE) if items else None
