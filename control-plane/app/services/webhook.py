import json
import hmac
import hashlib
import urllib.request
import logging
from app.services.ssrf_protection import get_safe_request_url_and_host

logger = logging.getLogger(__name__)

def dispatch_webhook(url: str, secret_token: str, payload: dict):
    safe_url, original_host = get_safe_request_url_and_host(url)
    
    if not safe_url or not original_host:
        logger.error(f"Webhook blockiert: URL {url} ist unsicher (SSRF-Prävention).")
        return

    try:
        payload_bytes = json.dumps(payload).encode('utf-8')
        signature = hmac.new(
            secret_token.encode('utf-8'),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        # Request wird gegen die feste IP ausgeführt, um DNS-Rebinding zu blockieren
        req = urllib.request.Request(safe_url, data=payload_bytes, method='POST')
        
        # Der originale Host-Header wird gesetzt, damit das Zielsystem richtig routet
        req.add_header('Host', original_host)
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Aegis-Signature', signature)
        
        with urllib.request.urlopen(req, timeout=10) as response:
            logger.info(f"Webhook erfolgreich an {url} gesendet. HTTP {response.status}")
    except Exception as e:
        logger.error(f"Webhook-Versand an {url} fehlgeschlagen: {str(e)}")
