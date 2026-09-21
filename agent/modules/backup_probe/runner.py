import os
import time
from typing import Dict, Any, List

def run(context: Dict[str, Any]) -> List[str]:
    """Prüft Backup-Verzeichnisse auf Aktualität (MVP-Ansatz für Systemhäuser)."""
    logger = context.get("logger")
    findings = []
    
    # Beispielhafte Pfade, die von gängigen Backup-Tools genutzt werden
    # Im echten MVP: Konfigurierbar über Control-Plane Parameter machen
    backup_paths = [
        "/var/log/backup.log",
        "C:\\BackupLogs\\latest.log"
    ]
    
    max_age_seconds = 86400 * 2  # Warnen, wenn Backup älter als 48 Stunden ist
    now = time.time()
    
    for path in backup_paths:
        if os.path.exists(path):
            file_age = now - os.path.getmtime(path)
            if file_age > max_age_seconds:
                findings.append(f"BACKUP_FAIL: Backup-Log '{path}' ist veraltet ({int(file_age/3600)} Stunden alt).")
            else:
                findings.append(f"BACKUP_PASS: Backup-Log '{path}' ist aktuell.")
        else:
            findings.append(f"BACKUP_INFO: Pfad '{path}' nicht gefunden.")

    if logger:
        for finding in findings:
            logger.log(f"AUDIT_RESULT: backup_probe - {finding}")
            
    return findings
