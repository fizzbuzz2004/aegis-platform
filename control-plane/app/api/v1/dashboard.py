from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
import json

from app.core.database import get_db
from app.core.security import get_current_admin_user
from app.models.orm import User, Tenant, ModuleResult, HostDevice

router = APIRouter()

@router.get("/dashboard/ui", response_class=HTMLResponse)
def get_dashboard_ui():
    return """
    <!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Aegis Compliance Console</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    </head>
    <body class="bg-slate-900 text-slate-100 font-sans min-h-screen p-8" x-data="dashboardApp()">
        <div class="max-w-7xl mx-auto">
            <header class="flex justify-between items-center mb-8 border-b border-slate-700 pb-4">
                <h1 class="text-2xl font-bold tracking-tight text-cyan-400">AEGIS // Security & Compliance Control</h1>
                <div class="flex gap-4">
                    <select x-model="filterStatus" class="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm">
                        <option value="ALL">Alle Status</option>
                        <option value="CRITICAL">Kritisch (&lt;70%)</option>
                        <option value="GOOD">Gut (&ge;90%)</option>
                    </select>
                    <input type="text" x-model="searchNorm" placeholder="Norm filtern (z.B. NIS2, ISO27001)" class="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm">
                </div>
            </header>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <template x-for="tenant in filteredTenants" :key="tenant.id">
                    <div class="bg-slate-800 border border-slate-700 rounded-lg p-6 shadow-xl cursor-pointer hover:border-cyan-500 transition-colors" @click="openDrawer(tenant)">
                        <div class="flex justify-between items-start mb-4">
                            <h2 class="text-lg font-semibold text-white" x-text="tenant.name"></h2>
                            <span class="text-2xl font-bold" :class="tenant.compliance_score >= 90 ? 'text-emerald-400' : (tenant.compliance_score >= 70 ? 'text-amber-400' : 'text-rose-500')" x-text="tenant.compliance_score + '%'"></span>
                        </div>
                        <div class="text-xs text-slate-400 space-y-1">
                            <p><strong>Hosts:</strong> <span x-text="tenant.host_count"></span> active</p>
                            <p><strong>Normen:</strong> <span x-text="tenant.standards.join(', ') || 'Keine'"></span></p>
                        </div>
                    </div>
                </template>
            </div>
        </div>

        <!-- Detail Drawer -->
        <div x-show="drawerOpen" class="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end" x-transition.opacity>
            <div class="w-full max-w-xl bg-slate-800 h-full p-6 overflow-y-auto border-l border-slate-700 shadow-2xl" @click.away="drawerOpen = false">
                <div class="flex justify-between items-center border-b border-slate-700 pb-4 mb-6">
                    <h3 class="text-xl font-bold text-cyan-400" x-text="selectedTenant?.name"></h3>
                    <button @click="drawerOpen = false" class="text-slate-400 hover:text-white">&times;</button>
                </div>
                
                <h4 class="text-sm font-bold uppercase text-slate-400 mb-3">Registrierte Hosts & Audit-Detail</h4>
                <div class="space-y-4">
                    <template x-for="host in selectedTenant?.hosts" :key="host.hostname">
                        <div class="bg-slate-900 border border-slate-700 rounded p-4">
                            <div class="flex justify-between items-center mb-2">
                                <span class="font-mono text-sm text-cyan-300" x-text="host.hostname"></span>
                                <span class="text-xs text-slate-500" x-text="host.os_info"></span>
                            </div>
                            <div class="space-y-2">
                                <template x-for="res in host.results" :key="res.module_name">
                                    <div class="text-xs bg-slate-800 p-2 rounded">
                                        <div class="flex justify-between text-slate-300 font-semibold mb-1">
                                            <span x-text="res.module_name"></span>
                                            <span x-text="res.timestamp"></span>
                                        </div>
                                        <template x-for="f in res.findings" :key="f.code">
                                            <div class="flex justify-between items-center py-0.5">
                                                <span class="text-slate-400" x-text="f.message"></span>
                                                <span class="px-1.5 py-0.5 rounded text-[10px] font-bold" :class="f.status === 'PASS' ? 'bg-emerald-950 text-emerald-400' : 'bg-rose-950 text-rose-400'" x-text="f.status"></span>
                                            </div>
                                        </template>
                                    </div>
                                </template>
                            </div>
                        </div>
                    </template>
                </div>
            </div>
        </div>

        <script>
            function dashboardApp() {
                return {
                    tenants: [],
                    filterStatus: 'ALL',
                    searchNorm: '',
                    drawerOpen: false,
                    selectedTenant: null,
                    async init() {
                        const token = localStorage.getItem('aegis_admin_token');
                        const res = await fetch('/api/v1/dashboard/data', { headers: { 'Authorization': `Bearer ${token}` } });
                        if(res.ok) {
                            const data = await res.json();
                            this.tenants = data.tenants;
                        }
                    },
                    get filteredTenants() {
                        return this.tenants.filter(t => {
                            const matchStatus = this.filterStatus === 'ALL' || (this.filterStatus === 'CRITICAL' && t.compliance_score < 70) || (this.filterStatus === 'GOOD' && t.compliance_score >= 90);
                            const matchNorm = !this.searchNorm || t.standards.some(s => s.toLowerCase().includes(this.searchNorm.toLowerCase()));
                            return matchStatus && matchNorm;
                        });
                    },
                    openDrawer(tenant) {
                        this.selectedTenant = tenant;
                        this.drawerOpen = true;
                    }
                }
            }
        </script>
    </body>
    </html>
    """

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
