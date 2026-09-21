import platform
from typing import Dict, Any, List

def run(context: Dict[str, Any]) -> List[str]:
    """Prüft Windows Registry Autostart-Schlüssel auf unautorisierte Einträge."""
    logger = context.get("logger")
    findings = []
    
    if platform.system().lower() != "windows":
        findings.append("REGISTRY_INFO: Nicht-Windows System, Check übersprungen.")
        return findings

    try:
        import winreg
        # Prüfe HKLM Run Key
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
        
        count = 0
        while True:
            try:
                name, value, type = winreg.EnumValue(key, count)
                # MVP-Logik: Warnung bei ungewöhnlichen Pfaden (z.B. AppData, Temp)
                if "AppData" in value or "Temp" in value:
                    findings.append(f"REGISTRY_WARN: Verdächtiger Autostart in HKLM: {name} -> {value}")
                else:
                    findings.append(f"REGISTRY_PASS: Autostart validiert: {name}")
                count += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except Exception as e:
        findings.append(f"REGISTRY_ERROR: Fehler beim Auslesen der Registry: {str(e)}")

    if logger:
        for finding in findings:
            logger.log(f"AUDIT_RESULT: registry_audit - {finding}")
            
    return findings
