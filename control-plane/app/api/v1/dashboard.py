from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
import json

from app.core.database import get_db
from app.core.security import get_current_admin_user
from app.models.orm import User, Tenant, ModuleResult

router = APIRouter()

@router.get("/dashboard/ui", response_class=HTMLResponse)
def get_dashboard_ui():
    html_content = """
    <!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Aegis MSP Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-100 p-8 font-sans">
        <div class="max-w-7xl mx-auto">
            <h1 class="text-3xl font-bold text-slate-800 mb-8">Aegis MSP Compliance Matrix</h1>
            <div id="grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <p class="text-slate-500">Lade Daten...</p>
            </div>
        </div>
        <script>
            async function loadDashboard() {
                const token = localStorage.getItem('aegis_admin_token');
                if (!token) {
                    document.getElementById('grid').innerHTML = '<p class="text-red-500">Nicht authentifiziert. Bitte Token im LocalStorage hinterlegen.</p>';
                    return;
                }
                
                try {
                    const res = await fetch('/api/v1/dashboard/data', {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                    if (!res.ok) throw new Error('API Request failed');
                    
                    const data = await res.json();
                    const grid = document.getElementById('grid');
                    grid.innerHTML = '';
                    
                    data.tenants.forEach(tenant => {
                        let bgColor = 'bg-green-100 border-green-500';
                        let statusText = '100% COMPLIANT';
                        let textColor = 'text-green-700';
                        
                        if (tenant.status === 'FAIL') {
                            bgColor = 'bg-red-100 border-red-500';
                            statusText = 'CRITICAL FAILURE';
                            textColor = 'text-red-700';
                        } else if (tenant.status === 'WARN') {
                            bgColor = 'bg-yellow-100 border-yellow-500';
                            statusText = 'WARNING';
                            textColor = 'text-yellow-700';
                        }

                        const standards = tenant.standards.join(', ') || 'Keine Standards erfasst';
                        
                        const card = `
                            <div class="border-l-4 rounded shadow bg-white p-6 ${bgColor}">
                                <h2 class="text-xl font-bold text-slate-800 mb-2">${tenant.name}</h2>
                                <p class="text-sm font-semibold ${textColor} mb-4">${statusText}</p>
                                <div class="text-sm text-slate-600">
                                    <p><strong>Standards:</strong> ${standards}</p>
                                    <p><strong>Aktive Hosts:</strong> ${tenant.host_count}</p>
                                </div>
                            </div>
                        `;
                        grid.innerHTML += card;
                    });
                } catch (e) {
                    document.getElementById('grid').innerHTML = '<p class="text-red-500">Fehler beim Laden der Daten.</p>';
                }
            }
            loadDashboard();
        </script>
    </body>
    </html>
    """
    return html_content

@router.get("/dashboard/data")
def get_dashboard_data(current_user: User = Depends(get_current_admin_user), db: Session = Depends(get_db)):
    tenants = db.query(Tenant).all()
    response_data = []

    for t in tenants:
        results = db.query(ModuleResult).filter(ModuleResult.tenant_id == t.id).all()
        status = 'PASS'
        standards_set = set()

        for r in results:
            try:
                findings = json.loads(r.findings)
                for f in findings:
                    if f.get("status") == "FAIL" or f.get("severity") in ["HIGH", "CRITICAL"]:
                        status = "FAIL"
                    elif f.get("status") == "WARN" and status != "FAIL":
                        status = "WARN"
                    
                    if "compliance" in f:
                        for c in f["compliance"]:
                            standards_set.add(c.split(":")[0])
            except Exception:
                continue

        response_data.append({
            "id": t.id,
            "name": t.name,
            "status": status,
            "standards": list(standards_set),
            "host_count": len(t.hosts)
        })

    return {"status": "success", "tenants": response_data}
