# The Legacy Server Breach: Incident Response Investigation

**Author:** Kristopher Neumann

A full incident-response investigation of a deliberately vulnerable legacy
Ubuntu server, run end-to-end through the five phases of the incident
response lifecycle: **Prepare → Detect & Analyze → Contain → Eradicate &
Recover → Report**. Every technical finding was verified by hand against
authoritative sources, in line with a "trust but verify" approach to
AI-assisted analysis described below.

## Why this project

I spent several years in technical recruiting, evaluating engineers and
understanding what strong technical work actually looks like, before
completing Per Scholas's Cybersecurity Analyst with AI Tools program to
move into hands-on security work. This project is where that transition
shows up directly: the investigation itself, and the discipline of
verifying AI output rather than trusting it.

## The scenario

A legacy Ubuntu server (`legacyserver`) supporting an internal application
triggered anomalous traffic alerts. As the responding analyst, I built an
isolated lab, investigated the breach, contained it without destroying
evidence, eradicated the root cause, and hardened the system against
recurrence — then documented the findings as both a technical report and
an automated verification script.

## Key findings

| Finding | Detail |
|---|---|
| **Unauthenticated root bindshell** | Port 1524 ran an `inetd`-spawned root shell — no authentication, no exploit required. |
| **Backdoored FTP service** | vsftpd matching the known-malicious 2.3.4 build (CVE-2011-2523, CVSS 9.8) — verified against NIST NVD, not taken on AI output alone. |
| **30 open ports** on a single host, including legacy/unencrypted services (telnet, plain FTP), an exposed build service (distcc), outdated Samba, and two unsupported databases. |
| **Surgical containment** | Blocked the two critical listeners with host firewall rules and process termination — without powering off the VM or destroying volatile evidence. |
| **Permanent remediation** | Removed the backdoor's `inetd` persistence mechanism and disabled four additional legacy remote-access services as defense-in-depth hardening. |
| **Automated verification** | Wrote and ran a Bash health-check script (`scripts/health_check.sh`) to confirm the fix holds. |

## AI as a force multiplier — with verification

Generative AI was used throughout as a research and drafting assistant,
under a strict rule: **every AI-sourced claim had to be independently
verified** before it went in the report.

A concrete example from this project: an AI assistant returned a
threat-intelligence table that included a CVSS score for a Samba
vulnerability. Rather than citing that score directly, I cross-referenced
every CVE against the NIST National Vulnerability Database, recording
the actual published date and CVSS vector for each one, and treated any
mismatch as a "failed verification" worth flagging in the report rather
than silently correcting. That discipline — using AI to move faster
without trusting it as ground truth — is the main process point of this
project.

## Repository structure

```
legacy-server-breach-investigation/
├── README.md
├── docs/                          # Phase-by-phase incident report
│   ├── Phase_1_Prepare.pdf
│   ├── Phase_2_Detect_Analyze.pdf
│   ├── Phase_3_Contain.pdf
│   ├── Phase_4_Eradicate_Recover.pdf
│   └── Phase_5_Report_Present.pdf
├── evidence/                      # Annotated screenshots per phase
│   └── ...
├── scripts/
│   └── health_check.sh            # Automated post-remediation verification
└── logs/                          # Raw tool output (scans, process lists, connections)
    └── ...
```

## Skills demonstrated

- Network segmentation and isolated lab design (VirtualBox/UTM)
- Reconnaissance and service enumeration (`nmap`, NSE scripts)
- Vulnerability research and CVE/CVSS verification against NVD/MITRE
- Incident containment with evidence preservation (order of volatility)
- Linux system hardening (`inetd`, `iptables`, service minimization)
- Bash scripting for automated security verification
- Technical documentation and incident reporting
- Disciplined, verification-first use of AI tooling

## Lab note

This investigation was performed entirely inside an isolated virtual lab
using intentionally vulnerable training VMs provided as part of the Per
Scholas curriculum. No production systems, real organizations, or
real-world targets were involved. The lab network was later rebuilt on an
isolated virtual network (from an initial bridged configuration) to
properly segment it from the host network — a correction made and
documented during the project itself.

## Contact

Kristopher Neumann — www.linkedin.com/in/krisneumann · krisgneumann@gmail.com
