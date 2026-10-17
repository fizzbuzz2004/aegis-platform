# control-plane/app/services/webhook.py
import json
import hmac
import hashlib
import urllib.request
import urllib.error
import logging
from app.services.ssrf_protection import get_safe_request_url_and_host

logger = logging.getLogger(__name__)

def dispatch_webhook(url: str, secret_token: str, payload: dict) -> bool:
    """
    Sendet einen Webhook mit SSRF-Schutz, HMAC-Signatur und robuster Fehlerbehandlung.
    Gibt True bei erfolgreicher Zustellung (HTTP 2xx) und False bei Fehlern zurück,
    damit Aufrufer (wie der Outbox-Worker) Wiederholungen (Retries) korrekt steuern können.
    """
    safe_url, original_host = get_safe_request_url_and_host(url)
    
    if not safe_url or not original_host:
        logger.error(f"Webhook blockiert: URL {url} ist unsicher (SSRF-Prävention).")
        return False

    try:
        payload_bytes = json.dumps(payload).encode('utf-8')
        signature = hmac.new(
            secret_token.encode('utf-8'),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        req = urllib.request.Request(safe_url, data=payload_bytes, method='POST')
        req.add_header('Host', original_host)
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Aegis-Signature', signature)
        
        with urllib.request.urlopen(req, timeout=10) as response:
            if 200 <= response.status < 300:
                logger.info(f"Webhook erfolgreich an {url} gesendet. HTTP {response.status}")
                return True
            else:
                logger.warning(f"Webhook an {url} mit unerwartetem Status beantwortet: HTTP {response.status}")
                return False
    except urllib.error.HTTPError as e:
        logger.error(f"Webhook-Versand an {url} fehlgeschlagen (HTTP-Fehler {e.code}): {e.reason}")
        return False
    except Exception as e:
        logger.error(f"Webhook-Versand an {url} fehlgeschlagen: {str(e)}")
        return False
