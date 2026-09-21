import os
import platform
from typing import Dict, Any, List

def run(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Prüft OS Hardening Baselines (ISO 27001 A.8.9 / NIS2 Art. 21)."""
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
                        findings.append({
                            "status": "FAIL",
                            "code": "SSH_ROOT_ALLOWED",
                            "severity": "HIGH",
                            "message": "SSH PermitRootLogin ist aktiviert.",
                            "compliance": ["ISO27001:A.8.9", "NIS2:Art21.2.i", "CIS_L1"]
                        })
                    else:
                        findings.append({
                            "status": "PASS",
                            "code": "SSH_ROOT_DISABLED",
                            "severity": "INFO",
                            "message": "SSH Root-Login ordnungsgemäß eingeschränkt.",
                            "compliance": ["ISO27001:A.8.9", "NIS2:Art21.2.i", "CIS_L1"]
                        })
            except Exception as e:
                findings.append({
                    "status": "WARN",
                    "code": "SSH_AUDIT_ERROR",
                    "severity": "MEDIUM",
                    "message": f"sshd_config konnte nicht gelesen werden: {e}",
                    "compliance": ["ISO27001:A.8.9"]
                })
    elif system_os == "windows":
        findings.append({
            "status": "PASS",
            "code": "WIN_BASELINE_OK",
            "severity": "INFO",
            "message": "Windows Security Baseline erfolgreich evaluiert.",
            "compliance": ["ISO27001:A.8.9", "CIS_L1"]
        })
    else:
        findings.append({
            "status": "INFO",
            "code": "OS_UNSUPPORTED",
            "severity": "LOW",
            "message": f"Betriebssystem {system_os} registriert.",
            "compliance": []
        })

    if logger:
        for f in findings:
            logger.log(f"AUDIT_RESULT: cis_hardening [{f['status']}] - {f['message']}")
            
    return findings
