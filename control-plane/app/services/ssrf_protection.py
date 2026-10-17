import socket
import ipaddress
from urllib.parse import urlparse
import logging
from typing import Tuple, Optional
import http.client
import ssl

logger = logging.getLogger(__name__)

class PinningHTTPConnection(http.client.HTTPConnection):
    """HTTP-Connection mit erzwungenem IP-Pinning zur Verhinderung von DNS-Rebinding (TOCTOU)."""
    def __init__(self, target_ip: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_ip = target_ip

    def connect(self):
        # Verbindung wird strikt zur vorab validierten IP aufgebaut, nicht zum Hostnamen
        self.sock = socket.create_connection(
            (self.target_ip, self.port),
            self.timeout,
            self.source_address
        )


class PinningHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS-Connection mit IP-Pinning und erzwungenem SNI-Hostheader."""
    def __init__(self, target_ip: str, original_host: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_ip = target_ip
        self.original_host = original_host

    def connect(self):
        # Verbindung zur fixierten IP aufbauen
        sock = socket.create_connection(
            (self.target_ip, self.port),
            self.timeout,
            self.source_address
        )
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        
        # SNI (Server Name Indication) auf den originalen Hostnamen erzwingen
        context = self._context or ssl.create_default_context()
        self.sock = context.wrap_socket(sock, server_hostname=self.original_host)


def get_safe_request_url_and_host(url: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Löst die IP auf, prüft auf SSRF / Private IPs und gibt die validierte IP 
    sowie den Original-Host für das Pinning zurück.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None, None
            
        hostname = parsed.hostname
        if not hostname:
            return None, None

        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        try:
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
            return None, None

        # Strikte Prüfung JEDER aufgelösten IP gegen SSRF-Vektoren
        for ip_obj in resolved_ips:
            if (ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_link_local or 
                ip_obj.is_multicast or 
                ip_obj.is_reserved or 
                ip_obj.is_unspecified):
                logger.warning(f"SSRF-Schutz: Blockierte unsichere IP {ip_obj} für Ziel {url}")
                return None, None

        # IP-Pinning: Verwende die verifizierte IP direkt
        target_ip = str(resolved_ips[0])
        return target_ip, hostname

    except Exception as e:
        logger.error(f"URL-Validierung fehlgeschlagen: {e}")
        return None, None
