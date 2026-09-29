import pytest
from unittest.mock import patch
import urllib.error
from app.services.psa_adapter import PSADispatcher
from app.models.orm import ModuleResult

def test_psa_dispatch_timeout_triggers_dlq(db):
    tenant_id = 1
    hostname = "test-host-01"
    
    # Ändere .invalid zu einer echten Domain, damit der SSRF-Check nicht wegen DNS abbricht
    webhook_url = "https://example.com/webhook"
    
    secret = "secret_token_abc"
    
    payload = {
        "tenant_id": tenant_id,
        "hostname": hostname,
        "module_name": "cis_hardening",
        "findings": [
            {
                "status": "FAIL",
                "code": "SSH_ROOT_ALLOWED",
                "severity": "HIGH",
                "message": "PermitRootLogin ist aktiv",
                "compliance": ["ISO27001:A.8.9"]
            }
        ]
    }

    # Simulation eines echten Netzwerkausfalls/Timeouts über Mocking von urlopen
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection timed out")):
        PSADispatcher.dispatch_event(
            url=webhook_url,
            secret_token=secret,
            payload=payload,
            previous_state_failed=False,
            db=db
        )

    # Verifiziere, dass der Fehler sauber in der Dead-Letter-Queue gepuffert wurde
    dlq_entry = db.query(ModuleResult).filter(
        ModuleResult.tenant_id == tenant_id,
        ModuleResult.module_name == "DEAD_LETTER_QUEUE"
    ).first()

    assert dlq_entry is not None, "Dead-Letter-Queue-Eintrag wurde bei Netzwerkausfall nicht erstellt!"
    assert "PSA_DISPATCH_FAILED" in dlq_entry.findings
    assert "Dauerhafter Zustellungsfehler" in dlq_entry.findings
