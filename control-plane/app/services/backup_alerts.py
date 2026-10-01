import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.orm import ModuleResult, PSAAlertState, Tenant, WebhookConfig
from app.services.psa_adapter import PSADispatcher

logger = logging.getLogger(__name__)
BACKUP_MODULE = "backup_probe"
ALERT_AGE = timedelta(hours=48)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _read_findings(result: ModuleResult) -> list[dict]:
    try:
        findings = json.loads(result.findings)
        return findings if isinstance(findings, list) else []
    except (TypeError, json.JSONDecodeError):
        return [{"status": "ERROR", "severity": "HIGH", "code": "INVALID_RESULT", "message": "Backup probe returned unreadable findings."}]


def _is_failed(findings: list[dict]) -> bool:
    return any(
        str(finding.get("status", "")).upper() in {"FAIL", "ERROR", "STALE"}
        or str(finding.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
        for finding in findings
    )


def _failure_started_at(db: Session, latest: ModuleResult) -> datetime:
    history = (
        db.query(ModuleResult)
        .filter(
            ModuleResult.tenant_id == latest.tenant_id,
            ModuleResult.hostname == latest.hostname,
            ModuleResult.module_name == BACKUP_MODULE,
        )
        .order_by(ModuleResult.timestamp.desc(), ModuleResult.id.desc())
        .all()
    )
    started_at = _as_utc(latest.timestamp)
    for result in history:
        if not _is_failed(_read_findings(result)):
            break
        started_at = _as_utc(result.timestamp)
    return started_at


def evaluate_backup_alerts(db: Session, now: datetime | None = None) -> int:
    """Create one PSA ticket per tenant/host when backup state is failing or stale for 48h."""
    current_time = _as_utc(now or datetime.now(timezone.utc))
    rows = (
        db.query(ModuleResult)
        .filter(ModuleResult.module_name == BACKUP_MODULE)
        .order_by(ModuleResult.tenant_id, ModuleResult.hostname, ModuleResult.timestamp.desc(), ModuleResult.id.desc())
        .all()
    )
    latest_by_host: dict[tuple[int, str], ModuleResult] = {}
    for result in rows:
        latest_by_host.setdefault((result.tenant_id, result.hostname), result)

    created_tickets = 0
    for latest in latest_by_host.values():
        latest_at = _as_utc(latest.timestamp)
        latest_findings = _read_findings(latest)
        failed = _is_failed(latest_findings)
        stale = current_time - latest_at >= ALERT_AGE
        failure_since = _failure_started_at(db, latest) if failed else latest_at
        is_alertable = (failed and current_time - failure_since >= ALERT_AGE) or stale

        state = db.query(PSAAlertState).filter_by(
            tenant_id=latest.tenant_id,
            hostname=latest.hostname,
            module_name=BACKUP_MODULE,
        ).first()
        if state is None:
            state = PSAAlertState(
                tenant_id=latest.tenant_id,
                hostname=latest.hostname,
                module_name=BACKUP_MODULE,
            )
            db.add(state)

        if not is_alertable:
            state.failing_since = failure_since if failed else None
            if not failed:
                state.ticket_created_at = None
            db.flush()
            continue

        incident_started_at = failure_since if failed else latest_at
        state.failing_since = incident_started_at
        if state.ticket_created_at is not None:
            db.flush()
            continue

        tenant = db.query(Tenant).filter(Tenant.id == latest.tenant_id).first()
        webhooks = db.query(WebhookConfig).filter(
            WebhookConfig.tenant_id == latest.tenant_id,
            WebhookConfig.is_active.is_(True),
        ).all()
        if not tenant or not webhooks:
            db.flush()
            continue

        findings = latest_findings
        if not failed:
            findings = findings + [{
                "status": "FAIL",
                "severity": "HIGH",
                "code": "BACKUP_STALE",
                "message": "No backup probe result has been received for at least 48 hours.",
                "compliance": [],
            }]
        dispatch_payload = {
            "tenant_id": latest.tenant_id,
            "hostname": latest.hostname,
            "module_name": BACKUP_MODULE,
            "findings": findings,
            "incident_started_at": incident_started_at.isoformat(),
            "company_id": tenant.psa_company_id,
            "site_id": tenant.psa_site_id,
        }
        all_delivered = True
        for webhook in webhooks:
            delivered = PSADispatcher.dispatch_event(
                url=webhook.url,
                secret_token=webhook.secret_token,
                payload=dispatch_payload,
                previous_state_failed=False,
                db=db,
                provider=webhook.provider,
                auth_header=webhook.auth_header,
                auth_value=webhook.auth_value,
            )
            all_delivered = all_delivered and delivered
        if all_delivered:
            state.ticket_created_at = current_time
            created_tickets += 1
        db.flush()

    db.commit()
    return created_tickets