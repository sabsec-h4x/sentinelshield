# ─────────────────────────────────────────────────────────────────
#  core/geo_reputation.py — GeoIP + IP Reputation Scoring
#
#  WHAT DOES THIS DO?
#  For every request, we look up:
#  1. Which COUNTRY the IP is from
#  2. Is this IP from a known BAD source? (Tor, VPN, datacenter)
#  3. What is its REPUTATION SCORE?
#
#  WHY DOES GEOGRAPHY MATTER?
#  If your app only serves users in India, and suddenly you get
#  10,000 requests from Eastern Europe — that's suspicious.
#  GeoIP lets you block entire regions if needed.
#
#  IP REPUTATION SOURCES:
#  • Tor exit nodes     — used to hide attacker identity
#  • Known VPN ranges   — often used to bypass rate limits
#  • Datacenter IPs     — unusual for real human users
#  • Threat intelligence — IPs seen in previous attacks globally
#
#  NOTE: For production, use MaxMind GeoIP2 database.
#  For this project, we use a lightweight approach with
#  ipapi.co (free tier) + local reputation lists.
# ─────────────────────────────────────────────────────────────────

import sys
import os
import ipaddress
from dataclasses import dataclass, field
from typing import Optional, List

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Try httpx for API calls
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


@dataclass
class GeoReputation:
    """Complete geo + reputation data for an IP address."""
    ip_address:    str
    country_code:  str   = "XX"     # ISO 2-letter code (US, IN, RU...)
    country_name:  str   = "Unknown"
    city:          str   = "Unknown"
    region:        str   = "Unknown"
    isp:           str   = "Unknown"
    asn:           str   = ""

    # Reputation flags
    is_tor:        bool  = False    # Tor exit node
    is_vpn:        bool  = False    # Known VPN provider
    is_datacenter: bool  = False    # Cloud/datacenter IP (not residential)
    is_proxy:      bool  = False    # Open proxy
    is_bogon:      bool  = False    # Fake/private/reserved IP

    # Reputation score: 0 = clean, 100 = very suspicious
    reputation_score: float = 0.0
    risk_flags:    List[str] = field(default_factory=list)


# ── Known Bad IP Ranges (Simplified Threat Intelligence) ─────────
# In production, these would come from commercial threat intel feeds
# updated daily. For this project we include key ranges.

# Known Tor exit node ranges (partial — real list has 1000s of IPs)
TOR_INDICATORS = [
    "185.220.", "185.107.", "199.87.154.", "162.247.72.",
    "171.25.193.", "176.10.99.", "77.109.139.", "80.67.172.",
]

# Known datacenter/cloud ranges
DATACENTER_RANGES = [
    "3.",     # AWS us-east-1
    "52.",    # AWS
    "54.",    # AWS
    "13.",    # AWS
    "35.",    # GCP
    "34.",    # GCP
    "104.",   # Cloudflare/various
    "185.",   # Various datacenters
    "167.",   # Various datacenters
]

# High-risk country codes (configure based on your app's audience)
# These are NOT automatically blocked — just flagged for extra scrutiny
HIGH_RISK_COUNTRIES = {
    "KP": "North Korea",    # Almost all traffic is malicious
    "BY": "Belarus",
}

# Reserved/private IP ranges — should never appear as real client IPs
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
]


class GeoReputationChecker:
    """
    Checks IP geolocation and reputation.

    Uses ipapi.co for geo data (free, no API key needed for low volume).
    Falls back to local analysis if API is unavailable.
    """

    def __init__(self):
        self._cache = {}  # Simple in-memory cache: {ip: GeoReputation}
        print("✅ GeoIP + Reputation checker ready")

    def check(self, ip_address: str) -> GeoReputation:
        """
        Main method: get geo + reputation data for an IP.
        Results are cached so we don't re-check the same IP every request.
        """
        # Return cached result if available
        if ip_address in self._cache:
            return self._cache[ip_address]

        result = GeoReputation(ip_address=ip_address)

        # Step 1: Check if it's a private/bogon IP
        if self._is_private(ip_address):
            result.is_bogon      = True
            result.country_code  = "LO"
            result.country_name  = "Local/Private Network"
            result.risk_flags.append("Private IP address")
            # Don't cache private IPs (common in dev environments)
            return result

        # Step 2: Check local reputation lists (fast, no API needed)
        self._check_local_reputation(ip_address, result)

        # Step 3: Try to get geo data from API (best effort)
        try:
            self._fetch_geo_data(ip_address, result)
        except Exception:
            pass  # Geo lookup failed — continue with local data only

        # Step 4: Check country reputation
        if result.country_code in HIGH_RISK_COUNTRIES:
            result.risk_flags.append(f"High-risk country: {result.country_name}")
            result.reputation_score = min(100, result.reputation_score + 20)

        # Cache the result
        self._cache[ip_address] = result
        return result

    def _is_private(self, ip_str: str) -> bool:
        """Check if IP is private/reserved."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in PRIVATE_RANGES)
        except ValueError:
            return False

    def _check_local_reputation(self, ip: str, result: GeoReputation):
        """Fast local checks against known bad IP ranges."""

        # Check Tor indicators
        if any(ip.startswith(prefix) for prefix in TOR_INDICATORS):
            result.is_tor = True
            result.risk_flags.append("Known Tor exit node range")
            result.reputation_score = min(100, result.reputation_score + 40)

        # Check datacenter ranges
        first_octet = ip.split(".")[0] + "."
        if any(ip.startswith(dc) for dc in DATACENTER_RANGES):
            result.is_datacenter = True
            result.risk_flags.append("Datacenter/cloud IP (not residential)")
            result.reputation_score = min(100, result.reputation_score + 15)

    def _fetch_geo_data(self, ip: str, result: GeoReputation):
        """
        Fetch geolocation from ipapi.co (free, no key needed).
        Timeout of 2 seconds so it doesn't slow down requests.
        """
        if not HTTPX_AVAILABLE:
            return

        try:
            with httpx.Client(timeout=2.0) as client:
                resp = client.get(f"https://ipapi.co/{ip}/json/")
                if resp.status_code == 200:
                    data = resp.json()
                    if "error" not in data:
                        result.country_code = data.get("country_code", "XX")
                        result.country_name = data.get("country_name", "Unknown")
                        result.city         = data.get("city",         "Unknown")
                        result.region       = data.get("region",       "Unknown")
                        result.isp          = data.get("org",          "Unknown")
                        result.asn          = str(data.get("asn",      ""))
        except Exception:
            pass  # API unavailable — use local data only

    def get_blocked_countries(self) -> List[str]:
        """Return list of country codes that are auto-blocked."""
        return list(HIGH_RISK_COUNTRIES.keys())


# ── Singleton ─────────────────────────────────────────────────────
geo_checker = GeoReputationChecker()
