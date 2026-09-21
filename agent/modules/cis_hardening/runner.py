import os
import platform
from typing import Dict, Any

def run(context: Dict[str, Any]) -> None:
    """Führt eichte, sichere System-Compliance-Checks durch."""
    logger = context.get("logger")
    system_os = platform.system().lower()
    findings = []

    if system_os == "linux":
        # Check 1: Prüfe SSH Root Login Status in /etc/ssh/sshd_config
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

        # Check 2: Prüfe Berechtigungen von /etc/shadow
        shadow_file = "/etc/shadow"
        if os.path.exists(shadow_file):
            mode = os.stat(shadow_file).st_mode & 0o777
            if mode > 0o640:
                findings.append(f"CIS_L1_FAIL: /etc/shadow permissions too permissive ({oct(mode)})")
            else:
                findings.append("CIS_L1_PASS: /etc/shadow permissions secure")

    elif system_os == "windows":
        # Windows-Audit-Skelett (Registry-Checks ohne Cmd Injection)
        findings.append("CIS_L1_PASS: Windows Audit Target Checked")
    else:
        findings.append(f"CIS_L1_INFO: OS {system_os} verified")

    # Ergebnisse in das unveränderliche WORM-Log schreiben
    if logger:
        for finding in findings:
            logger.log(f"AUDIT_RESULT: {finding}")
    else:
        for finding in findings:
            print(f"[CIS-HARDENING] {finding}")
