from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
import json
import os
import base64
import re

from app.core.database import get_db
from app.core.security import assert_tenant_access, get_current_tenant_user
from app.models.orm import User, UserRole, Tenant, ModuleResult, HostDevice

router = APIRouter()


def _dashboard_logo(encoded_logo: str | None) -> str | None:
    if not encoded_logo:
        return None
    value = encoded_logo.strip()
    if value.startswith("data:"):
        header, separator, value = value.partition(",")
        if not separator or header not in {
            "data:image/png;base64",
            "data:image/jpeg;base64",
            "data:image/gif;base64",
        }:
            return None
    try:
        image = base64.b64decode(value, validate=True)
    except ValueError:
        return None
    if image.startswith(b"\x89PNG\r\n\x1a\n"):
        mime_type = "image/png"
    elif image.startswith(b"\xff\xd8\xff"):
        mime_type = "image/jpeg"
    elif image.startswith((b"GIF87a", b"GIF89a")):
        mime_type = "image/gif"
    else:
        return None
    if len(image) > 2 * 1024 * 1024:
        return None
    return f"data:{mime_type};base64,{base64.b64encode(image).decode('ascii')}"


@router.get("/dashboard/ui", response_class=HTMLResponse)
def get_dashboard_ui():
    template_path = os.path.join(os.path.dirname(__file__), "../../templates/dashboard.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>Dashboard-Template nicht gefunden.</h3>", 404

@router.get("/dashboard/data")
def get_dashboard_data(current_user: User = Depends(get_current_tenant_user), db: Session = Depends(get_db)):
    tenant_query = db.query(Tenant)
    if current_user.role == UserRole.CUSTOMER_ADMIN:
        tenant_query = tenant_query.filter(Tenant.id == current_user.tenant_id)
    tenants = tenant_query.all()
    response_data = []

    for t in tenants:
        assert_tenant_access(current_user, t.id)
        results = db.query(ModuleResult).filter(ModuleResult.tenant_id == t.id).all()
        hosts = db.query(HostDevice).filter(HostDevice.tenant_id == t.id).all()
        
        latest_by_host_module = {}
        for result in sorted(
            results,
            key=lambda item: item.timestamp.timestamp() if item.timestamp else float("-inf"),
            reverse=True,
        ):
            latest_by_host_module.setdefault((result.hostname, result.module_name), result)

        total_checks = 0
        passed_checks = 0
        standards_set = set()

        for r in latest_by_host_module.values():
            try:
                findings = json.loads(r.findings)
                if not isinstance(findings, list):
                    continue
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    finding_status = str(f.get("status", "")).upper()
                    if finding_status in {"PASS", "FAIL"}:
                        total_checks += 1
                        passed_checks += finding_status == "PASS"
                    references = f.get("compliance", [])
                    if isinstance(references, list):
                        standards_set.update(
                            reference.split(":", 1)[0]
                            for reference in references
                            if isinstance(reference, str)
                        )
            except (TypeError, json.JSONDecodeError):
                continue

        score = round((passed_checks / total_checks) * 100) if total_checks > 0 else None

        host_details = []
        for h in hosts:
            h_results = db.query(ModuleResult).filter(ModuleResult.tenant_id == t.id, ModuleResult.hostname == h.hostname).all()
            parsed_results = []
            host_passed = 0
            host_checks = 0
            for hr in h_results:
                try:
                    f_list = json.loads(hr.findings)
                    if not isinstance(f_list, list):
                        f_list = []
                except (TypeError, json.JSONDecodeError):
                    f_list = []
                parsed_results.append({
                    "module_name": hr.module_name,
                    "timestamp": hr.timestamp.strftime("%Y-%m-%d %H:%M"),
                    "findings": f_list
                })
            host_latest_results = [
                result for (hostname, _), result in latest_by_host_module.items()
                if hostname == h.hostname
            ]
            for result in host_latest_results:
                try:
                    findings = json.loads(result.findings)
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(findings, list):
                    continue
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    finding_status = str(finding.get("status", "")).upper()
                    if finding_status in {"PASS", "FAIL"}:
                        host_checks += 1
                        host_passed += finding_status == "PASS"
            latest_checkin = max(
                (result.timestamp for result in h_results if result.timestamp),
                default=None,
            )
            host_details.append({
                "hostname": h.hostname,
                "os_info": h.os_info,
                "results": parsed_results,
                "compliance_score": round(host_passed * 100 / host_checks) if host_checks else None,
                "evaluated_checks": host_checks,
                "last_checkin": latest_checkin.strftime("%Y-%m-%d %H:%M") if latest_checkin else None,
                "is_active": h.is_active,
            })

        response_data.append({
            "id": t.id,
            "name": t.name,
            "logo_url": _dashboard_logo(t.logo_base64),
            "brand_color_hex": t.brand_color_hex if re.fullmatch(r"#[0-9a-fA-F]{6}", t.brand_color_hex or "") else "#0f766e",
            "custom_footer": t.custom_footer,
            "compliance_score": score,
            "evaluated_checks": total_checks,
            "passed_checks": passed_checks,
            "standards": list(standards_set),
            "host_count": len(hosts),
            "hosts": host_details
        })

    return {"status": "success", "tenants": response_data}
