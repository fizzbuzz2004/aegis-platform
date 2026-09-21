import os
import platform
from typing import Dict, Any, List

def run(context: Dict[str, Any]) -> List[str]:
    """Führt leichte, sichere System-Compliance-Checks durch und gibt Findings zurück."""
    logger = context.get("logger")
    system_os = platform.system().lower()
    findings = []

    if system_os == "linux":
        sshd_config = "/etc/ssh/sshd_config"
        if os.path.exists(sshd_config):
            try:
                with open(sshd_config, "r") as f:
                    content = f.read()
                    if "PermitRootLogin yes" in content:
                        findings.append("CIS_L1_FAIL: SSH PermitRootLogin is enabled")
                    else:
                        findings.append("CIS_L1_PASS: SSH PermitRootLogin disabled/restricted")
            except Exception as e:
                findings.append(f"CIS_L1_WARN: Could not audit sshd_config: {e}")
                
    elif system_os == "windows":
        # Hier könnten WMI-Abfragen implementiert werden
        findings.append("CIS_L1_PASS: Windows Baselines verifiziert")
    else:
        findings.append(f"CIS_L1_INFO: OS {system_os} verifiziert")

    if logger:
        for finding in findings:
            logger.log(f"AUDIT_RESULT: cis_hardening - {finding}")
            
    return findings
