import socket
import ipaddress
from urllib.parse import urlparse
import logging
from typing import Tuple, Optional, List

logger = logging.getLogger(__name__)

def get_safe_request_url_and_host(url: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Löst die URL auf, prüft alle zugehörigen IPs (IPv4/IPv6) auf SSRF-Risiken 
    (inkl. DNS-Rebinding und Multi-IP-Bypasses) und gibt eine sichere IP-basierte URL 
    sowie den originalen Host-Header zurück.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None, None
            
        hostname = parsed.hostname
        if not hostname:
            return None, None

        # 1. Prüfen, ob der Hostname bereits eine direkte IP-Adresse ist
        try:
            direct_ip = ipaddress.ip_address(hostname)
            resolved_ips = [direct_ip]
        except ValueError:
            # Kein IP-Literal, daher DNS-Auflösung aller Records via getaddrinfo (IPv4 & IPv6)
            try:
                # Port ermitteln (Standard 80 für HTTP, 443 für HTTPS)
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                addr_info = socket.getaddrinfo(hostname, port)
            except socket.gaierror as e:
                logger.error(f"SSRF-Schutz: DNS-Auflösung für {hostname} fehlgeschlagen: {e}")
                return None, None

            resolved_ips = []
            for family, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0]
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    resolved_ips.append(ip_obj)
                except ValueError:
                    continue

        if not resolved_ips:
            logger.warning(f"SSRF-Schutz: Keine gültigen IPs für Ziel {url} gefunden.")
            return None, None

        # 2. Strikte Prüfung JEDER aufgelösten IP (Verhinderung von DNS-Rebinding / Round-Robin-Bypasses)
        for ip_obj in resolved_ips:
            if (ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_link_local or 
                ip_obj.is_multicast or 
                ip_obj.is_reserved or 
                ip_obj.is_unspecified):
                logger.warning(f"SSRF-Schutz: Blockierte unsichere IP {ip_obj} für Ziel {url} (Hostname: {hostname})")
                return None, None

        # 3. Verwendung der ersten verifizierten IP für das IP-Pinning
        target_ip_obj = resolved_ips[0]
        ip_str = str(target_ip_obj)

        # Korrekte Formatierung für IPv6 vs IPv4 in der URL (Netloc)
        if target_ip_obj.version == 6:
            netloc = f"[{ip_str}]"
        else:
            netloc = ip_str

        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
            
        # Rekonstruktion der URL mit der fixierten IP, während der originale Hostname als Header übergeben wird
        safe_url = parsed._replace(netloc=netloc).geturl()
        return safe_url, hostname

    except Exception as e:
        logger.error(f"URL-Validierung fehlgeschlagen: {e}")
        return None, None
