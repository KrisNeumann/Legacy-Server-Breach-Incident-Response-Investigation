#!/bin/bash
#
# health_check.sh
# Automated Health Check — Incident Response Investigation: The Legacy Server Breach
#
# Verifies that the services remediated during the incident response
# (vsftpd backdoor, root bindshell, unnecessary rsh-family/telnet services,
# Samba, distccd, and UnrealIRCd) remain closed after remediation.
#
# Author: Kristopher Neumann
#
# Usage:
#   ./health_check.sh [target_ip]
#   If no target_ip is given, defaults to the value below.

TARGET_IP="${1:-192.168.1.207}"
CRITICAL_PORTS=(21 23 512 513 514 1524 139 445 3632 6667 6697)
TIMEOUT=2
FAILED_CHECKS=0

echo "=============================================="
echo " AUTOMATED HEALTH CHECK AUDIT | Target: ${TARGET_IP}"
echo " Analyst: Kristopher Neumann | Workstation: soc-analyst-vm"
echo " Timestamp: $(date)"
echo "=============================================="

echo -n "[*] Auditing System Availability (ICMP Ping)... "
if ping -c 2 -W 2 "${TARGET_IP}" > /dev/null 2>&1; then
    echo "[ONLINE]"
else
    echo "[CRITICAL: HOST UNREACHABLE]"
    exit 1
fi

echo ""
echo "[*] Auditing Neutralized & Hardened Port Boundaries:"
echo "----------------------------------------------"

for PORT in "${CRITICAL_PORTS[@]}"; do
    nc -z -w "${TIMEOUT}" "${TARGET_IP}" "${PORT}" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[-] ALERT: TCP Port ${PORT} is OPEN! [VULNERABLE / UNHARDENED]"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        echo "[+] VERIFIED: TCP Port ${PORT} is CLOSED/DROPPED. [SECURE]"
    fi
done

echo "----------------------------------------------"
if [ ${FAILED_CHECKS} -eq 0 ]; then
    echo "[RESULT: SECURE] Target ${TARGET_IP} successfully passed all validation checks."
    exit 0
else
    echo "[RESULT: NON-COMPLIANT] ${FAILED_CHECKS} unauthorized services detected!"
    exit 1
fi
