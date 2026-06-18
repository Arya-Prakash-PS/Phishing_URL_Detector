"""
AuthentURL - Phishing URL Detection Engine
==========================================
A comprehensive rule-based phishing detection system that analyzes URLs
using cybersecurity heuristics and assigns a risk score.

Author: AuthentURL Team
"""

import re
import ssl
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

import dns.resolver
import requests
import whois

# ─────────────────────────────────────────────────────────────────────────────
# Constants & Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Known legitimate / trusted domains (bypass list)
TRUSTED_DOMAINS = {
    "google.com", "www.google.com",
    "youtube.com", "www.youtube.com",
    "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com",
    "amazon.com", "www.amazon.com",
    "facebook.com", "www.facebook.com",
    "instagram.com", "www.instagram.com",
    "twitter.com", "www.twitter.com",
    "x.com", "www.x.com",
    "linkedin.com", "www.linkedin.com",
    "netflix.com", "www.netflix.com",
    "paypal.com", "www.paypal.com",
    "github.com", "www.github.com",
    "stackoverflow.com",
    "wikipedia.org", "www.wikipedia.org",
}

# Brands to detect impersonation
IMPERSONATED_BRANDS = [
    "google", "amazon", "microsoft", "paypal", "facebook",
    "instagram", "apple", "netflix", "linkedin", "twitter", "x",
    "ebay", "chase", "wellsfargo", "bankofamerica", "citibank",
    "dropbox", "adobe", "yahoo", "outlook", "office365",
]

# Suspicious top-level domains
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".tk", ".gq", ".ml", ".cf", ".ga",
    ".pw", ".icu", ".buzz", ".live", ".cam", ".link", ".online",
    ".site", ".website", ".fun", ".space", ".club", ".loan",
    ".win", ".bid", ".trade", ".date", ".racing", ".review",
    ".stream", ".download", ".zip", ".mov",
}

# Well-known URL shortener services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "shorturl.at", "goo.gl",
    "ow.ly", "buff.ly", "adf.ly", "tiny.cc", "is.gd",
    "rb.gy", "cutt.ly", "shorte.st", "linktr.ee", "bl.ink",
}

# Keywords that indicate phishing intent
PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "banking", "password", "signin", "confirm", "wallet",
    "payment", "credential", "authentication", "validation",
    "suspended", "recovery", "reset", "alert", "urgent",
    "limited", "expire", "click-here", "webscr", "paypal",
    "ebayisapi", "billing",
]

# Suspicious characters often used to obfuscate URLs
SUSPICIOUS_SYMBOLS = ["@", "%", "//", "=", "&"]

# Scoring weights
SCORES = {
    "ip_address":           20,
    "no_https":             15,
    "excessive_length":     10,
    "excessive_dots":       10,
    "suspicious_symbols":    5,
    "url_encoding":          5,
    "hyphenated_domain":     8,
    "brand_impersonation":  30,
    "suspicious_tld":       15,
    "url_shortener":        20,
    "keyword_hit":           5,  # per keyword
    "new_domain":           20,  # domain < 30 days old
    "hidden_whois":         10,
    "no_ssl":               15,
    "invalid_ssl":          10,
    "dns_failure":          15,
    "unreachable":          10,
    "excessive_subdomains":  8,
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _extract_parts(url: str) -> dict:
    """Parse a URL into its component parts."""
    try:
        parsed = urllib.parse.urlparse(url)
        # If scheme is missing, add it so urlparse works properly
        if not parsed.scheme:
            parsed = urllib.parse.urlparse("http://" + url)

        hostname = parsed.hostname or ""
        # Strip 'www.' for cleaner domain comparison
        bare_domain = hostname.lower()
        if bare_domain.startswith("www."):
            bare_domain = bare_domain[4:]

        # Extract TLD
        parts = bare_domain.split(".")
        tld = f".{parts[-1]}" if len(parts) > 1 else ""

        return {
            "scheme":    parsed.scheme.lower(),
            "hostname":  hostname.lower(),
            "bare":      bare_domain,
            "path":      parsed.path,
            "query":     parsed.query,
            "fragment":  parsed.fragment,
            "tld":       tld,
            "subdomains": parts[:-2] if len(parts) > 2 else [],
            "full":      url,
        }
    except Exception:
        return {}


def _is_ip_address(hostname: str) -> bool:
    """Return True if hostname is an IPv4 or IPv6 address."""
    ipv4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    ipv6 = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")
    return bool(ipv4.match(hostname) or ipv6.match(hostname))


# ─────────────────────────────────────────────────────────────────────────────
# Detection Checks
# ─────────────────────────────────────────────────────────────────────────────

def check_ip_address(parts: dict) -> Optional[dict]:
    """Detect IP address used as host (e.g., http://192.168.1.1/login)."""
    if _is_ip_address(parts.get("hostname", "")):
        return {
            "rule":        "IP Address as Host",
            "description": "The URL uses a raw IP address instead of a domain name. Legitimate websites rarely do this.",
            "score":       SCORES["ip_address"],
            "severity":    "high",
        }
    return None


def check_https(parts: dict) -> Optional[dict]:
    """Verify HTTPS usage."""
    if parts.get("scheme") != "https":
        return {
            "rule":        "No HTTPS",
            "description": "The URL uses HTTP instead of HTTPS. Without encryption, data can be intercepted.",
            "score":       SCORES["no_https"],
            "severity":    "medium",
        }
    return None


def check_url_length(url: str) -> Optional[dict]:
    """Flag excessively long URLs (> 75 characters)."""
    if len(url) > 75:
        return {
            "rule":        "Excessive URL Length",
            "description": f"URL length ({len(url)} chars) is unusually long. Phishing URLs often embed extra data to confuse users.",
            "score":       SCORES["excessive_length"],
            "severity":    "low",
        }
    return None


def check_excessive_dots(parts: dict) -> Optional[dict]:
    """Detect an excessive number of dots / subdomains."""
    subdomains = parts.get("subdomains", [])
    hostname   = parts.get("hostname", "")
    dot_count  = hostname.count(".")

    if dot_count >= 4 or len(subdomains) >= 3:
        return {
            "rule":        "Excessive Subdomains / Dots",
            "description": f"The domain has {dot_count} dots and {len(subdomains)} subdomains. Attackers use deep subdomain chains to disguise malicious domains.",
            "score":       SCORES["excessive_dots"],
            "severity":    "medium",
        }
    return None


def check_suspicious_symbols(url: str) -> Optional[dict]:
    """Detect suspicious symbols in the URL."""
    found = []
    if "@" in url:
        found.append("@ (can redirect to a different host)")
    # Double slash after the scheme is normal; extra ones are suspicious
    if url.count("//") > 1:
        found.append("// (double slash used for redirection)")
    # Detect hex encoding like %20, %2F, etc.
    if re.search(r"%[0-9a-fA-F]{2}", url):
        found.append("% (URL-encoded characters used for obfuscation)")

    if found:
        return {
            "rule":        "Suspicious Symbols Detected",
            "description": f"Suspicious characters found: {', '.join(found)}.",
            "score":       SCORES["suspicious_symbols"],
            "severity":    "medium",
        }
    return None


def check_url_encoding(url: str) -> Optional[dict]:
    """Detect heavy URL encoding / obfuscation."""
    # Count percent-encoded sequences
    encoded = re.findall(r"%[0-9a-fA-F]{2}", url)
    if len(encoded) >= 3:
        return {
            "rule":        "URL Encoding / Obfuscation",
            "description": f"Found {len(encoded)} URL-encoded sequences ({', '.join(encoded[:5])}). This is often used to hide the true destination.",
            "score":       SCORES["url_encoding"],
            "severity":    "medium",
        }
    return None


def check_hyphens(parts: dict) -> Optional[dict]:
    """Detect hyphens in the registered domain."""
    bare = parts.get("bare", "")
    # Count hyphens in the second-level domain (not subdomains/TLD)
    domain_parts = bare.split(".")
    sld = domain_parts[0] if domain_parts else ""
    if sld.count("-") >= 1:
        return {
            "rule":        "Hyphenated Domain",
            "description": f"The domain '{bare}' contains hyphens. Phishers often use hyphens to mimic legitimate brands (e.g., paypal-secure.com).",
            "score":       SCORES["hyphenated_domain"],
            "severity":    "medium",
        }
    return None


def check_brand_impersonation(parts: dict) -> Optional[dict]:
    """Detect brand impersonation in hostname."""
    hostname = parts.get("hostname", "")
    bare     = parts.get("bare", "")

    for brand in IMPERSONATED_BRANDS:
        # Skip if the bare domain IS the trusted brand
        if bare in TRUSTED_DOMAINS or hostname in TRUSTED_DOMAINS:
            continue
        if brand in hostname and bare != f"{brand}.com":
            return {
                "rule":        "Brand Impersonation Detected",
                "description": f"The URL contains the brand name '{brand}' in a domain that is NOT the official website. This is a classic phishing technique.",
                "score":       SCORES["brand_impersonation"],
                "severity":    "critical",
            }
    return None


def check_suspicious_tld(parts: dict) -> Optional[dict]:
    """Detect suspicious / free TLDs commonly used for phishing."""
    tld = parts.get("tld", "")
    if tld in SUSPICIOUS_TLDS:
        return {
            "rule":        f"Suspicious TLD ({tld})",
            "description": f"The domain uses the TLD '{tld}', which is frequently abused for phishing and spam.",
            "score":       SCORES["suspicious_tld"],
            "severity":    "high",
        }
    return None


def check_url_shortener(parts: dict) -> Optional[dict]:
    """Detect known URL shortener services."""
    hostname = parts.get("hostname", "")
    bare     = parts.get("bare", "")
    for svc in URL_SHORTENERS:
        if hostname == svc or bare == svc:
            return {
                "rule":        "URL Shortener Detected",
                "description": f"The URL uses the shortening service '{svc}'. Short URLs hide the true destination and are commonly used in phishing campaigns.",
                "score":       SCORES["url_shortener"],
                "severity":    "high",
            }
    return None


def check_phishing_keywords(url: str) -> list[dict]:
    """Detect suspicious phishing keywords in the URL path/query."""
    url_lower = url.lower()
    hits = []
    for kw in PHISHING_KEYWORDS:
        if kw in url_lower:
            hits.append(kw)

    if hits:
        return [{
            "rule":        "Suspicious Keywords Found",
            "description": f"Phishing-related keywords detected in the URL: {', '.join(hits)}. These words are commonly used to trick users.",
            "score":       SCORES["keyword_hit"] * len(hits),
            "severity":    "medium",
        }]
    return []


def check_excessive_subdomains(parts: dict) -> Optional[dict]:
    """Flag when there are >= 3 subdomain levels."""
    subdomains = parts.get("subdomains", [])
    if len(subdomains) >= 3:
        return {
            "rule":        "Excessive Subdomains",
            "description": f"The URL has {len(subdomains)} subdomain levels ({'.'.join(subdomains)}). Attackers embed legitimate-looking brand names as subdomains.",
            "score":       SCORES["excessive_subdomains"],
            "severity":    "medium",
        }
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Network & Security Checks
# ─────────────────────────────────────────────────────────────────────────────

def check_dns(hostname: str) -> Optional[dict]:
    """Verify DNS resolution."""
    try:
        dns.resolver.resolve(hostname, "A")
        return None  # DNS resolves fine
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.Timeout, Exception):
        return {
            "rule":        "DNS Resolution Failed",
            "description": f"The domain '{hostname}' could not be resolved via DNS. This may indicate a fake or misconfigured domain.",
            "score":       SCORES["dns_failure"],
            "severity":    "high",
        }


def check_ssl(hostname: str, port: int = 443) -> Optional[dict]:
    """Check SSL/TLS certificate validity."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=5),
            server_hostname=hostname
        ) as ssock:
            cert = ssock.getpeercert()
            # Check expiry
            expire_str = cert.get("notAfter", "")
            if expire_str:
                expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                if expire_dt < datetime.now():
                    return {
                        "rule":        "Expired SSL Certificate",
                        "description": "The SSL certificate has expired. This is a significant security risk.",
                        "score":       SCORES["invalid_ssl"],
                        "severity":    "high",
                    }
        return None  # SSL is valid
    except ssl.SSLCertVerificationError:
        return {
            "rule":        "Invalid SSL Certificate",
            "description": "The SSL certificate could not be verified. The site may be spoofing a legitimate domain.",
            "score":       SCORES["invalid_ssl"],
            "severity":    "high",
        }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {
            "rule":        "No SSL Certificate",
            "description": "The domain does not support HTTPS or has no SSL certificate on port 443.",
            "score":       SCORES["no_ssl"],
            "severity":    "medium",
        }
    except Exception:
        return None  # Inconclusive — don't penalise


def check_reachability(hostname: str) -> Optional[dict]:
    """Check if the domain is reachable over HTTP/HTTPS."""
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{hostname}",
                timeout=5,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (AuthentURL Security Scanner)"},
            )
            if r.status_code < 500:
                return None  # Reachable
        except Exception:
            continue
    return {
        "rule":        "Domain Unreachable",
        "description": f"The domain '{hostname}' could not be reached. It may be a fake or abandoned domain.",
        "score":       SCORES["unreachable"],
        "severity":    "medium",
    }


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS / Domain Age Checks
# ─────────────────────────────────────────────────────────────────────────────

def check_whois(hostname: str) -> list[dict]:
    """Perform WHOIS lookup; check domain age and privacy protection."""
    results = []
    try:
        w = whois.whois(hostname)

        # ── Domain Age ──────────────────────────────────────────────────────
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            # Make both tz-aware for comparison
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - creation).days

            if age_days < 30:
                results.append({
                    "rule":        "Newly Registered Domain",
                    "description": f"The domain was registered only {age_days} day(s) ago. Phishing domains are often created shortly before an attack.",
                    "score":       SCORES["new_domain"],
                    "severity":    "critical",
                })
            elif age_days < 180:
                results.append({
                    "rule":        "Recently Registered Domain",
                    "description": f"The domain was registered {age_days} days ago (less than 6 months). While not definitive, newer domains are more likely to be used in phishing.",
                    "score":       SCORES["new_domain"] // 2,
                    "severity":    "medium",
                })

        # ── Hidden WHOIS ─────────────────────────────────────────────────────
        registrant = w.get("registrant_name") or w.get("org") or ""
        emails     = w.get("emails") or []
        if not registrant and not emails:
            results.append({
                "rule":        "Hidden WHOIS Information",
                "description": "The domain's WHOIS record is hidden or uses a privacy service. Legitimate organisations usually have public registration data.",
                "score":       SCORES["hidden_whois"],
                "severity":    "medium",
            })

    except Exception:
        # WHOIS lookup failed — treat as unknown; don't penalise heavily
        results.append({
            "rule":        "WHOIS Lookup Failed",
            "description": "Could not retrieve WHOIS information for this domain. Domain registration details are unavailable.",
            "score":       5,
            "severity":    "low",
        })

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Main Analyser
# ─────────────────────────────────────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """
    Run all detection checks against *url* and return a structured report.

    Returns
    -------
    dict with keys:
        url            – original URL
        score          – total integer risk score
        classification – 'Safe' | 'Suspicious' | 'Phishing'
        flags          – list of triggered rule dicts
        recommendations – list of advice strings
        is_trusted     – bool, whether domain is in whitelist
    """
    url = url.strip()

    # ── Parse URL ────────────────────────────────────────────────────────────
    parts = _extract_parts(url)
    if not parts:
        return {
            "url":             url,
            "score":           100,
            "classification":  "Phishing",
            "flags":           [{
                "rule":        "Invalid URL",
                "description": "The URL could not be parsed. It may be malformed.",
                "score":       100,
                "severity":    "critical",
            }],
            "recommendations": ["Do not visit this URL."],
            "is_trusted":      False,
        }

    hostname = parts["hostname"]
    bare     = parts["bare"]

    # ── Trusted-domain fast-path ─────────────────────────────────────────────
    if bare in TRUSTED_DOMAINS or hostname in TRUSTED_DOMAINS:
        return {
            "url":             url,
            "score":           0,
            "classification":  "Safe",
            "flags":           [],
            "recommendations": [
                "This is a well-known trusted domain.",
                "Always double-check the URL in your browser's address bar.",
            ],
            "is_trusted":      True,
        }

    # ── Run all rule checks ──────────────────────────────────────────────────
    flags: list[dict] = []

    # URL structure checks (fast, no network)
    for fn in [
        lambda: check_ip_address(parts),
        lambda: check_https(parts),
        lambda: check_url_length(url),
        lambda: check_excessive_dots(parts),
        lambda: check_suspicious_symbols(url),
        lambda: check_url_encoding(url),
        lambda: check_hyphens(parts),
        lambda: check_brand_impersonation(parts),
        lambda: check_suspicious_tld(parts),
        lambda: check_url_shortener(parts),
        lambda: check_excessive_subdomains(parts),
    ]:
        result = fn()
        if result:
            flags.append(result)

    # Keyword checks (returns list)
    flags.extend(check_phishing_keywords(url))

    # Network checks (slower — run only if not already very high risk)
    if hostname and not _is_ip_address(hostname):
        dns_flag = check_dns(hostname)
        if dns_flag:
            flags.append(dns_flag)
        else:
            # Only check SSL / reachability if DNS resolves
            ssl_flag = check_ssl(hostname)
            if ssl_flag:
                flags.append(ssl_flag)

            reach_flag = check_reachability(hostname)
            if reach_flag:
                flags.append(reach_flag)

            # WHOIS (slowest)
            flags.extend(check_whois(hostname))

    # ── Calculate total score ────────────────────────────────────────────────
    total_score = sum(f["score"] for f in flags)

    # ── Classify ─────────────────────────────────────────────────────────────
    if total_score <= 20:
        classification = "Safe"
    elif total_score <= 50:
        classification = "Suspicious"
    else:
        classification = "Phishing"

    # ── Build recommendations ────────────────────────────────────────────────
    recommendations = _build_recommendations(flags, classification)

    return {
        "url":             url,
        "score":           total_score,
        "classification":  classification,
        "flags":           flags,
        "recommendations": recommendations,
        "is_trusted":      False,
    }


def _build_recommendations(flags: list[dict], classification: str) -> list[str]:
    """Generate human-readable security recommendations based on triggered rules."""
    rec = []
    rule_names = {f["rule"] for f in flags}

    if classification == "Phishing":
        rec.append("🚨 Do NOT visit this URL. It shows strong indicators of a phishing attack.")
    elif classification == "Suspicious":
        rec.append("⚠️  Exercise extreme caution before visiting this URL.")

    if "No HTTPS" in rule_names:
        rec.append("Always look for HTTPS (padlock icon) before entering credentials.")
    if "Brand Impersonation Detected" in rule_names:
        rec.append("Always verify the official domain of a company before logging in.")
    if "URL Shortener Detected" in rule_names:
        rec.append("Expand shortened URLs using a preview tool before clicking.")
    if "Newly Registered Domain" in rule_names:
        rec.append("Be very wary of recently registered domains — common in phishing campaigns.")
    if "IP Address as Host" in rule_names:
        rec.append("Legitimate websites use domain names, not raw IP addresses.")
    if "Suspicious Keywords Found" in rule_names:
        rec.append("Be suspicious of URLs asking you to 'verify', 'login', or 'confirm' via a link.")
    if "DNS Resolution Failed" in rule_names:
        rec.append("This domain does not appear to exist. Do not proceed.")
    if not rec:
        rec.append("No major red flags detected, but always stay vigilant online.")

    rec.append("When in doubt, contact the organisation directly through their official website.")
    return rec
