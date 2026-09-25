import socket
import ipaddress
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

def is_safe_url(url: str) -> bool:
    """
    Verifiziert URLs auf SSRF (Server-Side Request Forgery) Versuche.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
            
        hostname = parsed.hostname
        if not hostname:
            return False

        # Host auflösen, um DNS-Rebinding zu verhindern
        ip_address = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_address)
        
        # Blockiert RFC1918, Loopback und Link-Local Adressen
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
            logger.warning(f"SSRF-Schutz: Blockierte IP {ip_address} für Ziel {url}")
            return False
            
        return True
    except Exception as e:
        logger.error(f"URL-Validierung fehlgeschlagen: {e}")
        return False
