import socket
import ipaddress
from urllib.parse import urlparse
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

def get_safe_request_url_and_host(url: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Löst die URL auf, prüft auf SSRF und gibt die sichere IP-basierte URL 
    sowie den originalen Host-Header (zur Verhinderung von DNS-Rebinding) zurück.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None, None
            
        hostname = parsed.hostname
        if not hostname:
            return None, None

        # DNS-Auflösung zur direkten Nutzung
        ip_address = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_address)
        
        # Blockiert RFC1918, Loopback und Multicast strikt
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
            logger.warning(f"SSRF-Schutz: Blockierte interne IP {ip_address} für Ziel {url}")
            return None, None
            
        # Rekonstruktion der URL mit der aufgelösten, sicheren IP
        netloc = ip_address
        if parsed.port:
            netloc = f"{ip_address}:{parsed.port}"
            
        safe_url = parsed._replace(netloc=netloc).geturl()
        return safe_url, hostname
    except Exception as e:
        logger.error(f"URL-Validierung fehlgeschlagen: {e}")
        return None, None
