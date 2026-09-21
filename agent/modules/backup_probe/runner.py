import os
import time
import platform
from typing import Dict, Any, List

def run(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Prüft Backup-Protokolle auf Aktualität (ISO 27001 A.8.13 / NIS2 Art. 21)."""
    logger = context.get("logger")
    findings = []
    
    if platform.system().lower() == "windows":
        backup_paths = ["C:\\BackupLogs\\latest.log", "C:\\ProgramData\\Veeam\\Backup.log"]
    else:
        backup_paths = ["/var/log/backup.log", "/var/log/syslog"]
    
    max_age_seconds = 86400 * 2  # Max. 48 Stunden alt
    now = time.time()
    
    for path in backup_paths:
        if os.path.exists(path):
            file_age = now - os.path.getmtime(path)
            if file_age > max_age_seconds:
                item = {
                    "status": "FAIL",
                    "code": "BACKUP_STALE",
                    "severity": "HIGH",
                    "message": f"Backup-Log '{path}' ist veraltet ({int(file_age/3600)}h alt).",
                    "compliance": ["ISO27001:A.8.13", "NIS2:Art21.2.c"]
                }
            else:
                item = {
                    "status": "PASS",
                    "code": "BACKUP_OK",
                    "severity": "INFO",
                    "message": f"Backup-Log '{path}' ist aktuell.",
                    "compliance": ["ISO27001:A.8.13", "NIS2:Art21.2.c"]
                }
        else:
            item = {
                "status": "WARN",
                "code": "BACKUP_NOT_FOUND",
                "severity": "MEDIUM",
                "message": f"Backup-Pfad '{path}' nicht gefunden.",
                "compliance": ["ISO27001:A.8.13"]
            }
        findings.append(item)

    if logger:
        for f in findings:
            logger.log(f"AUDIT_RESULT: backup_probe [{f['status']}] - {f['message']}")
            
    return findings
