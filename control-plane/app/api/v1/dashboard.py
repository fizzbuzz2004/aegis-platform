from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
import json
import os

from app.core.database import get_db
from app.core.security import get_current_admin_user
from app.models.orm import User, Tenant, ModuleResult, HostDevice

router = APIRouter()

@router.get("/dashboard/ui", response_class=HTMLResponse)
def get_dashboard_ui():
    template_path = os.path.join(os.path.dirname(__file__), "../../templates/dashboard.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>Dashboard-Template nicht gefunden.</h3>", 404

@router.get("/dashboard/data")
def get_dashboard_data(current_user: User = Depends(get_current_admin_user), db: Session = Depends(get_db)):
    tenants = db.query(Tenant).all()
    response_data = []

    for t in tenants:
        results = db.query(ModuleResult).filter(ModuleResult.tenant_id == t.id).all()
        hosts = db.query(HostDevice).filter(HostDevice.tenant_id == t.id).all()
        
        total_checks = 0
        passed_checks = 0
        standards_set = set()

        for r in results:
            try:
                findings = json.loads(r.findings)
                for f in findings:
                    total_checks += 1
                    if f.get("status") == "PASS":
                        passed_checks += 1
                    if "compliance" in f:
                        for c in f["compliance"]:
                            standards_set.add(c.split(":")[0])
            except Exception:
                continue

        score = int((passed_checks / total_checks) * 100) if total_checks > 0 else 100

        host_details = []
        for h in hosts:
            h_results = db.query(ModuleResult).filter(ModuleResult.tenant_id == t.id, ModuleResult.hostname == h.hostname).all()
            parsed_results = []
            for hr in h_results:
                try:
                    f_list = json.loads(hr.findings)
                except Exception:
                    f_list = []
                parsed_results.append({
                    "module_name": hr.module_name,
                    "timestamp": hr.timestamp.strftime("%Y-%m-%d %H:%M"),
                    "findings": f_list
                })
            host_details.append({
                "hostname": h.hostname,
                "os_info": h.os_info,
                "results": parsed_results
            })

        response_data.append({
            "id": t.id,
            "name": t.name,
            "compliance_score": score,
            "standards": list(standards_set),
            "host_count": len(hosts),
            "hosts": host_details
        })

    return {"status": "success", "tenants": response_data}
