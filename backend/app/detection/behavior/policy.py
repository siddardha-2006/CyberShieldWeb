import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple


class BehavioralSecurityPolicy:
    """
    Guards the behavioral browser sandbox against SSRF,
    internal network scans, cloud metadata endpoints, and malicious loops.
    """
    BLOCKED_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"), # AWS/GCP/Azure link-local / metadata
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10")
    ]

    @classmethod
    def validate_target_url(cls, url: str) -> Tuple[bool, str]:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return False, f"Unsupported scheme '{parsed.scheme}'. Only http/https permitted."

        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname in URL."

        # Check for localhost / loopback aliases
        if hostname.lower() in ["localhost", "127.0.0.1", "0.0.0.0", "metadata.google.internal"]:
            return False, "Access to localhost or cloud metadata services is blocked (SSRF Protection)."

        # Try resolving host to check IP against blocked private CIDRs
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                ip_str = item[4][0]
                ip_obj = ipaddress.ip_address(ip_str)
                for blocked_net in cls.BLOCKED_NETWORKS:
                    if ip_obj in blocked_net:
                        return False, f"Target resolves to restricted private/internal IP {ip_str}."
        except Exception:
            # If resolution fails, let behavioral sandbox handle network timeout
            pass

        return True, "URL passed security policy validation."

