# control-plane/app/services/psa_adapter.py
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
    def _format_payload(cls, provider: str, payload: dict[str, Any]) -> dict[str, Any]:
        meta = payload.get("aegis_meta", {})
        title = f"Backup probe alert: {meta.get('hostname', 'unknown host')}"
        description = json.dumps(payload.get("findings", []), ensure_ascii=True)
        if provider == "autotask":
            return {"ticket": {"title": title, "description": description, "companyID": payload.get("company_id"), "configurationItemID": payload.get("site_id")}, "aegis_meta": meta}
        if provider == "connectwise":
            return {"summary": title, "initialDescription": description, "company": {"id": payload.get("company_id")}, "site": {"id": payload.get("site_id")}, "aegis_meta": meta}
        if provider == "ninjaone":
            return {"alert": {"subject": title, "body": description, "deviceName": meta.get("hostname")}, "aegis_meta": meta}
        if provider == "halopsa":
            return {"summary": title, "details": description, "client_id": payload.get("company_id"), "site_id": payload.get("site_id"), "aegis_meta": meta}
        return payload

    @classmethod
    def dispatch_event(
        cls,
        url: str,
        secret_token: str,
        payload: dict[str, Any],
        previous_state_failed: bool = False,
        db: Optional[Session] = None,
        provider: str = "generic",
        auth_header: Optional[str] = None,
        auth_value: Optional[str] = None,
    ) -> bool:
        safe_url, original_host = get_safe_request_url_and_host(url)
        if not safe_url or not original_host:
            logger.error(f"PSA Dispatch blockiert: URL {url} ist unsicher (SSRF-Prävention).")
            return False

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
            return True

        psa_payload = {
            "aegis_meta": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "tenant_id": payload.get("tenant_id"),
                "hostname": payload.get("hostname"),
                "module_name": payload.get("module_name"),
                "incident_started_at": payload.get("incident_started_at"),
            },
            "findings": payload.get("findings", []),
            "company_id": payload.get("company_id"),
            "site_id": payload.get("site_id"),
        }
        psa_payload = cls._format_payload(provider, psa_payload)

        payload_bytes = json.dumps(psa_payload).encode('utf-8')
        signature = cls._generate_signature(secret_token, payload_bytes)

        req = urllib.request.Request(safe_url, data=payload_bytes, method='POST')
        req.add_header('Host', original_host)
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Aegis-Signature', signature)
        incident_key = payload.get("incident_started_at", "current")
        req.add_header('X-Aegis-Idempotency-Key', f"{payload.get('tenant_id')}-{payload.get('hostname')}-{payload.get('module_name')}-{incident_key}-{action}")
        if auth_header and auth_value:
            req.add_header(auth_header, auth_value)

        success = False
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    if 200 <= response.status < 300:
                        logger.info(f"PSA Action {action} gesendet. HTTP {response.status}")
                        success = True
                        break
                    else:
                        logger.warning(f"PSA Dispatch Versuch {attempt + 1} unerwarteter HTTP-Status: {response.status}")
            except urllib.error.HTTPError as e:
                # Client-Fehler (4xx) sofort abbrechen (keine sinnlosen Wiederholungen bei Auth- oder Syntaxfehlern)
                if 400 <= e.code < 500:
                    logger.error(f"PSA Dispatch Client-Fehler (HTTP {e.code}): {e.reason}. Keine Wiederholung.")
                    break
                logger.warning(f"PSA Dispatch Versuch {attempt + 1} fehlgeschlagen (HTTP-Fehler {e.code}): {e.reason}")
            except urllib.error.URLError as e:
                logger.warning(f"PSA Dispatch Versuch {attempt + 1} Netzwerkfehler: {str(e)}")
            except Exception as e:
                logger.warning(f"PSA Dispatch Versuch {attempt + 1} unerwarteter Fehler: {str(e)}")

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
        return success
