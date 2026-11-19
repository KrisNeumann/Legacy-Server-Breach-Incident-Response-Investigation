#!/bin/bash
#
# health_check.sh
# SOC Automated Health Check — Legacy Server Breach Investigation
#
# Verifies that the services remediated during the incident response
# (vsftpd backdoor, root bindshell, and unnecessary rsh-family/telnet
# services) remain closed or filtered after hardening.
#
# Author: Kris Neumann
# Project: Cap 195 Capstone — The Legacy Server Breach
#
# Usage:
#   ./health_check.sh [target_ip]
#   If no target_ip is given, defaults to the value below.

TARGET_IP="${1:-192.168.x.x}"
CRITICAL_PORTS=(21 23 512 513 514 1524)
TIMEOUT=2
FAILED_CHECKS=0

echo "=============================================="
echo " SOC AUTOMATED HEALTH CHECK AUDIT | Target: ${TARGET_IP}"
echo " Analyst: Kris Neumann | Workstation: soc-analyst-vm"
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
