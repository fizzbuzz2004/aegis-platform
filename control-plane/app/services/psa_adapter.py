import json
import hmac
import hashlib
import urllib.request
import urllib.error
import logging
from typing import Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class PSADispatcher:
    """Bidirektionaler Adapter für PSA-Systeme (HaloPSA / Autotask) mit Idempotenz- und Auto-Resolve-Logik."""
    
    @staticmethod
    def _generate_signature(secret: str, payload_bytes: bytes) -> str:
        return hmac.new(secret.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()

    @classmethod
    def dispatch_event(cls, url: str, secret_token: str, payload: dict[str, Any], previous_state_failed: bool) -> None:
        """
        Wertet den aktuellen und vorherigen Status aus, um Ticket-Erstellung oder Auto-Close zu triggern.
        """
        current_status_failed = any(
            f.get('status') == 'FAIL' or f.get('severity') in ['HIGH', 'CRITICAL'] 
            for f in payload.get('findings', [])
        )

        action = "UPDATE"
        if current_status_failed and not previous_state_failed:
            action = "CREATE_TICKET"
        elif not current_status_failed and previous_state_failed:
            action = "RESOLVE_TICKET"
        elif not current_status_failed and not previous_state_failed:
            return  # Nichts zu tun, System war und ist gesund.

        psa_payload = {
            "aegis_meta": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "tenant_id": payload.get("tenant_id"),
                "hostname": payload.get("hostname"),
                "module_name": payload.get("module_name")
            },
            "findings": payload.get("findings", [])
        }

        payload_bytes = json.dumps(psa_payload).encode('utf-8')
        signature = cls._generate_signature(secret_token, payload_bytes)

        req = urllib.request.Request(url, data=payload_bytes, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Aegis-Signature', signature)
        req.add_header('X-Aegis-Idempotency-Key', f"{payload.get('hostname')}-{payload.get('module_name')}-{action}")

        # Retries & Backoff für robuste MSP-Integration
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    logger.info(f"PSA Action {action} dispatched to {url}. HTTP {response.status}")
                    break
            except urllib.error.URLError as e:
                logger.warning(f"PSA Dispatch attempt {attempt + 1} failed: {str(e)}")
                if attempt == 2:
                    logger.error(f"PSA Dispatch permanently failed for {url} after 3 attempts.")
