import json
import hmac
import hashlib
import urllib.request
import urllib.error
import logging
from typing import Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.orm import ModuleResult
from app.services.ssrf_protection import get_safe_request_url_and_host

logger = logging.getLogger(__name__)

class PSADispatcher:
    @staticmethod
    def _generate_signature(secret: str, payload_bytes: bytes) -> str:
        return hmac.new(secret.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()

    @classmethod
    def dispatch_event(cls, url: str, secret_token: str, payload: dict[str, Any], previous_state_failed: bool, db: Optional[Session] = None) -> None:
        # SSRF-Schutz & DNS-Rebinding Prävention
        safe_url, original_host = get_safe_request_url_and_host(url)
        if not safe_url or not original_host:
            logger.error(f"PSA Dispatch blockiert: URL {url} ist unsicher (SSRF-Prävention).")
            return

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
            return

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

        # Der Request wird direkt an die verifizierte IP (safe_url) gesendet
        req = urllib.request.Request(safe_url, data=payload_bytes, method='POST')
        
        # Der ursprüngliche Hostname wird im Host-Header mitgegeben
        req.add_header('Host', original_host)
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Aegis-Signature', signature)
        req.add_header('X-Aegis-Idempotency-Key', f"{payload.get('hostname')}-{payload.get('module_name')}-{action}")

        success = False
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    logger.info(f"PSA Action {action} gesendet. HTTP {response.status}")
                    success = True
                    break
            except urllib.error.URLError as e:
                logger.warning(f"PSA Dispatch Versuch {attempt + 1} fehlgeschlagen: {str(e)}")

        if not success and db:
            dlq_entry = ModuleResult(
                tenant_id=payload.get("tenant_id"),
                hostname=payload.get("hostname"),
                module_name="DEAD_LETTER_QUEUE",
                findings=json.dumps([{
                    "status": "FAIL",
                    "code": "PSA_DISPATCH_FAILED",
                    "severity": "HIGH",
                    "message": f"Dauerhafter Zustellungsfehler an PSA Endpoint: {url}",
                    "compliance": []
                }]),
                audit_meta={"failed_payload": psa_payload, "failed_at": datetime.now(timezone.utc).isoformat()}
            )
            db.add(dlq_entry)
            db.commit()
