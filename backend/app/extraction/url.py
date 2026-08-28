import re
import math
import socket
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Any, List
import tldextract


class UrlExtractor:
    IPV4_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    IPV6_REGEX = re.compile(r'^[0-9a-fA-F:]+$')

    # Known high-risk URL shorteners
    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", 
        "buff.ly", "cutt.ly", "rb.gy", "tiny.cc", "shorte.st", "v.gd"
    }

    # Free hosting / tunnel services heavily abused for phishing
    FREE_HOSTING_DOMAINS = {
        "ngrok.io", "ngrok-free.app", "loca.lt", "serveo.net", "trycloudflare.com",
        "firebaseapp.com", "web.app", "glitch.me", "repl.co", "000webhostapp.com",
        "pages.dev", "vercel.app", "netlify.app", "s3.amazonaws.com", 
        "blob.core.windows.net", "github.io", "surge.sh", "duckdns.org", "hopto.org"
    }

    # High-risk / disposable TLDs frequently abused in malware & phishing
    SUSPICIOUS_TLDS = {
        "xyz", "top", "tk", "icu", "buzz", "fit", "monster", "live", "rest", 
        "cf", "gq", "ga", "ml", "click", "quest", "work", "fun", "space", 
        "site", "website", "racing", "download", "stream", "bid", "loan", "win"
    }

    # Executable / dangerous file extensions
    DANGEROUS_EXTENSIONS = {
        ".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".apk", ".dmg", 
        ".iso", ".zip", ".rar", ".7z", ".tar.gz", ".docm", ".xlsm", ".hta", ".wsf"
    }

    # Open redirect parameter names
    OPEN_REDIRECT_PARAMS = {
        "url", "redirect", "target", "link", "dest", "destination", "next", "r", "out", "go", "return"
    }

    # Crypto seed phrase & wallet harvesting regex
    CRYPTO_HARVESTING_REGEX = re.compile(
        r'(?i)(wallet-recovery|seed[-_]?phrase|recovery[-_]?phrase|mnemonic|private[-_]?key|keystore|secret[-_]?phrase|restore[-_]?wallet|sync[-_]?wallet|claim[-_]?airdrop|metamask[-_]?sync|trustwallet[-_]?restore|phantom[-_]?auth|seed=)'
    )

    # Official legitimate domain mapping for high-value brands
    OFFICIAL_BRANDS = {
        "apple": ["apple.com", "icloud.com", "itunes.com"],
        "icloud": ["icloud.com", "apple.com"],
        "appleid": ["apple.com", "icloud.com"],
        "findmy": ["apple.com", "icloud.com"],
        "google": ["google.com", "google.co.in", "google.co.uk", "google.com.br", "gmail.com", "youtube.com"],
        "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "msn.com"],
        "paypal": ["paypal.com", "paypal.me"],
        "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.com.br", "aws.amazon.com"],
        "netflix": ["netflix.com"],
        "facebook": ["facebook.com", "fb.com", "meta.com"],
        "instagram": ["instagram.com"],
        "whatsapp": ["whatsapp.com", "wa.me"],
        "telegram": ["telegram.org", "t.me"],
        "binance": ["binance.com"],
        "metamask": ["metamask.io"],
        "coinbase": ["coinbase.com"],
        "chase": ["chase.com", "jpmorganchase.com"],
        "wellsfargo": ["wellsfargo.com"],
        "bankofamerica": ["bankofamerica.com", "bofa.com"],
        "sbi": ["onlinesbi.sbi", "sbi.co.in"],
        "hdfc": ["hdfcbank.com"],
        "icici": ["icicibank.com"]
    }

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    @classmethod
    def extract(cls, raw_url: str) -> Dict[str, Any]:
        url_clean = raw_url.strip()
        if not re.match(r'^[a-zA-Z]+://', url_clean):
            url_clean = 'http://' + url_clean
            
        parsed = urlparse(url_clean)
        extracted = tldextract.extract(url_clean)
        
        hostname = (parsed.hostname or "").lower()
        registered_domain = (extracted.registered_domain or hostname).lower()
        domain_name = extracted.domain.lower()
        suffix = extracted.suffix.lower()
        
        is_ipv4 = bool(cls.IPV4_REGEX.match(hostname))
        is_ipv6 = bool(cls.IPV6_REGEX.match(hostname.strip("[]"))) and ":" in hostname
        is_ip = is_ipv4 or is_ipv6
        
        # Check for punycode / non-ascii in hostname
        has_punycode = hostname.startswith("xn--") or any(ord(c) > 127 for c in hostname)
        
        # Subdomains
        subdomains = [s for s in extracted.subdomain.split('.') if s]
        subdomain_depth = len(subdomains)
        
        # Special character flags
        has_at_symbol = "@" in url_clean
        path_raw = unquote(parsed.path)
        has_double_slash_in_path = "//" in path_raw
        has_hex_encoding = "%" in url_clean
        
        # Hyphen & digit counts
        hyphen_count = hostname.count("-")
        digit_count_in_hostname = sum(1 for c in hostname if c.isdigit())
        
        # Shorteners & Free hosting
        is_shortener = registered_domain in cls.SHORTENER_DOMAINS or hostname in cls.SHORTENER_DOMAINS
        is_free_hosting = any(registered_domain == h or hostname.endswith("." + h) for h in cls.FREE_HOSTING_DOMAINS)
        is_suspicious_tld = suffix in cls.SUSPICIOUS_TLDS or any(suffix.endswith("." + t) for t in cls.SUSPICIOUS_TLDS)
        
        # Crypto wallet & seed harvesting detection
        full_url_lower = url_clean.lower()
        has_crypto_seed_solicitation = bool(cls.CRYPTO_HARVESTING_REGEX.search(full_url_lower))

        # Brand impersonation detection
        is_brand_impersonation = False
        impersonated_brand = None
        
        for brand, official_domains in cls.OFFICIAL_BRANDS.items():
            if re.search(rf"(?:^|[-_.0-9]){brand}(?:[-_.0-9]|$)", hostname) or brand in domain_name:
                if not any(registered_domain == off or registered_domain.endswith("." + off) for off in official_domains):
                    is_brand_impersonation = True
                    impersonated_brand = brand
                    break

        # Path & Query parameters
        query_params = parse_qs(parsed.query)
        path_segments = [p for p in path_raw.split('/') if p]
        path_depth = len(path_segments)
        
        has_credential_keywords = bool(
            re.search(r'(?i)(login|signin|verify|update|account|security|banking|wallet|kyc|otp|passcode|auth|confirm|restore|password|recover|unblock|session|seed)', url_clean)
        )
        
        # Dangerous extension detection
        path_lower = path_raw.lower()
        has_dangerous_ext = any(path_lower.endswith(ext) for ext in cls.DANGEROUS_EXTENSIONS)
        has_double_ext = bool(re.search(r'\.[a-zA-Z0-9]{2,4}\.(exe|scr|vbs|bat|cmd|ps1|apk|iso|hta)$', path_lower))
        
        # Open redirect detection
        query_keys = [k.lower() for k in query_params.keys()]
        has_open_redirect_param = any(param in cls.OPEN_REDIRECT_PARAMS for param in query_keys)
        
        # Query inspection (embedded email or base64 token)
        query_str = parsed.query
        has_embedded_email = "@" in query_str or any("@" in str(v) for v in query_params.values())
        has_base64_in_query = bool(re.search(r'(?:[A-Za-z0-9+/]{20,}={0,2})', query_str))
        
        # Scheme & Ports
        is_http = parsed.scheme.lower() == "http"
        has_custom_port = parsed.port is not None and parsed.port not in [80, 443]
        
        # Entropy
        entropy_score = round(cls._calculate_entropy(domain_name), 2)
        has_high_entropy = entropy_score >= 3.8 and len(domain_name) >= 10
        
        # DNS Resolution & Private IP check
        dns_ips = []
        is_private_ip = False
        try:
            if hostname and not is_ip:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(1.5)
                dns_ips = socket.gethostbyname_ex(hostname)[2]
                socket.setdefaulttimeout(old_timeout)
            elif is_ipv4:
                dns_ips = [hostname]
            
            for ip in dns_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                        is_private_ip = True
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return {
            "original_url": raw_url,
            "normalized_url": url_clean,
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "hostname": hostname,
            "domain": domain_name,
            "suffix": suffix,
            "registered_domain": registered_domain,
            "subdomains": subdomains,
            "subdomain_depth": subdomain_depth,
            "url_length": len(url_clean),
            "domain_length": len(domain_name),
            "port": parsed.port,
            "path": path_raw,
            "path_depth": path_depth,
            "query": parsed.query,
            "query_params": query_params,
            "query_param_count": len(query_params),
            "fragment": parsed.fragment,
            # Security Boolean Parameters
            "is_ip_address": is_ip,
            "is_ipv4": is_ipv4,
            "is_ipv6": is_ipv6,
            "has_punycode": has_punycode,
            "has_at_symbol": has_at_symbol,
            "has_double_slash_in_path": has_double_slash_in_path,
            "has_hex_encoding": has_hex_encoding,
            "hyphen_count": hyphen_count,
            "has_excessive_hyphens": hyphen_count >= 2,
            "digit_count_in_hostname": digit_count_in_hostname,
            "has_excessive_digits": digit_count_in_hostname >= 4,
            "is_shortener_domain": is_shortener,
            "is_free_hosting_domain": is_free_hosting,
            "is_suspicious_tld": is_suspicious_tld,
            "is_brand_impersonation": is_brand_impersonation,
            "impersonated_brand": impersonated_brand,
            "is_http": is_http,
            "has_custom_port": has_custom_port,
            "has_credential_keywords_in_path": has_credential_keywords,
            "has_crypto_seed_solicitation": has_crypto_seed_solicitation,
            "has_dangerous_extension": has_dangerous_ext,
            "has_double_extension": has_double_ext,
            "has_open_redirect_param": has_open_redirect_param,
            "has_embedded_email": has_embedded_email,
            "has_base64_in_query": has_base64_in_query,
            "entropy": entropy_score,
            "has_high_entropy": has_high_entropy,
            "dns_resolved_ips": dns_ips,
            "is_resolvable": len(dns_ips) > 0,
            "is_private_or_loopback_ip": is_private_ip
        }
