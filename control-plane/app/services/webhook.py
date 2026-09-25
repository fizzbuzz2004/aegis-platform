import json
import hmac
import hashlib
import urllib.request
import logging
from app.services.ssrf_protection import is_safe_url

logger = logging.getLogger(__name__)

def dispatch_webhook(url: str, secret_token: str, payload: dict):
    if not is_safe_url(url):
        logger.error(f"Webhook blockiert: URL {url} ist unsicher (SSRF-Prävention).")
        return

    try:
        payload_bytes = json.dumps(payload).encode('utf-8')
        signature = hmac.new(
            secret_token.encode('utf-8'),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        req = urllib.request.Request(url, data=payload_bytes, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Aegis-Signature', signature)
        
        with urllib.request.urlopen(req, timeout=10) as response:
            logger.info(f"Webhook erfolgreich an {url} gesendet. HTTP {response.status}")
    except Exception as e:
        logger.error(f"Webhook-Versand an {url} fehlgeschlagen: {str(e)}")
