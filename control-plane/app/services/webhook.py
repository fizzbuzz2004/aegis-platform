import json
import hmac
import hashlib
import urllib.request
import logging

logger = logging.getLogger(__name__)

def dispatch_webhook(url: str, secret_token: str, payload: dict):
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
            logger.info(f"Webhook dispatched to {url} successfully. HTTP {response.status}")
    except Exception as e:
        logger.error(f"Failed to dispatch webhook to {url}: {str(e)}")
