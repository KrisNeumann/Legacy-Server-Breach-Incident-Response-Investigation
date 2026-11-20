# Incident Response Investigation: The Legacy Server Breach

**Author:** Kristopher Neumann

A structured incident-response investigation of a deliberately vulnerable
legacy Ubuntu server, conducted end-to-end in an isolated virtual lab
across the incident response lifecycle: **Preparation → Detection &
Analysis → Containment → Eradication & Recovery → Post-Incident Review**.
Every technical finding was verified against authoritative sources before
being treated as fact, including findings sourced from AI-assisted
research, and every finding was mapped to NIST, CIS, and ISO 27001
controls with a risk rating and an owner.

## Why this project

I spent several years in technical recruiting, evaluating engineers and
learning what strong technical work actually looks like, before moving
into hands-on security work through a structured cybersecurity training
program. This project is where that transition shows up directly: the
investigation itself, and the discipline of verifying every claim rather
than trusting it on its face.

## The engagement

A legacy Ubuntu server (hostname `legacyserver`) running a deliberately
vulnerable configuration triggered anomalous traffic alerts in a
simulated SOC scenario. Acting as the responding analyst, I built an
isolated lab, investigated the breach, contained it without destroying
evidence, eradicated the root cause, and hardened the system against
recurrence — then documented the findings as a formal technical report
with an automated verification script.

## Key findings

| Finding | Detail |
|---|---|
| **Unauthenticated root bindshell** | Port 1524 ran a root shell via an `inetd` service entry — no authentication, no exploit required. |
| **Backdoored FTP service** | vsftpd matching the known-malicious 2.3.4 build (CVE-2011-2523, CVSS 9.8) — verified against NIST NVD, not taken on AI output alone. |
| **30 open ports** on a single host, including legacy/unencrypted services (telnet, plain FTP), an exposed build service (distcc), outdated Samba, and two unsupported databases. |
| **Surgical containment** | Blocked the two most critical listeners with host firewall rules and process termination — without powering off the host or destroying volatile evidence. |
| **Permanent remediation** | Removed the backdoor's `inetd` persistence mechanism, stopped and disabled Samba and distccd at the service level, and hardened four additional legacy remote-access services. |
| **Automated verification** | Wrote and ran a Bash health-check script (`scripts/health_check.sh`) to confirm the fixes hold. |

## From findings to risk — the GRC layer

The technical investigation (Sections 1-4) answers "what was wrong and how
was it fixed." Section 5 answers the question a GRC-focused reader
actually asks: what control failures let this happen, and what's the
systemic fix — not just the per-finding one.

- **Framework mapping** — every finding is mapped to NIST CSF 2.0, NIST
  SP 800-53 Rev 5, CIS Controls v8, and ISO/IEC 27001:2022 Annex A. The
  mapping shows the six findings aren't six unrelated problems — they
  trace back to two recurring control gaps (secure configuration/least
  functionality, and vulnerability/flaw remediation).
- **Risk register** — each finding scored by likelihood and impact, rated
  from Medium to Critical before remediation, with an assigned risk
  owner and treatment decision, down to a verified Low residual risk.
- **Root-cause / policy gap analysis** — four process-level failures
  (no patch management program, no asset inventory, no hardening
  baseline, no change management review) that explain why all six
  findings existed on the same host at once.
- **Post-incident review** — a lessons-learned pass on the investigation
  process itself, including a process gap it catches in its own earlier
  work: UnrealIRCd's remediation was initially incomplete (terminated
  but not disabled at boot) until a follow-up step closed it.

Full writeup: [`docs/Section_5_Post_Incident_Review.pdf`](docs/Section_5_Post_Incident_Review.pdf).

## AI as a force multiplier — with verification

Generative AI was used throughout as a research and drafting assistant,
under a strict rule: **every AI-sourced claim had to be independently
verified** before it went in the report.

A concrete example from this investigation: an AI assistant returned a
threat-intelligence profile that included a CVSS score of 8.5 for a
Samba vulnerability (CVE-2007-2447). Cross-referencing that score against
the NIST National Vulnerability Database turned up a different number —
NVD's own CVSS v2.0 score for that CVE is 6.0. Rather than quietly using
whichever number looked better, the discrepancy was logged in the report
as a **Failed Verification**, and the lower, authoritative score was the
one used going forward. That's the actual behavior this project is built
around: using AI to move faster without treating it as ground truth.

## Repository structure

```
Incident_Response_Investigation/
├── README.md
├── docs/                          # Section-by-section incident report
│   ├── Section_1_Preparation.pdf
│   ├── Section_2_Detection_Analysis.pdf
│   ├── Section_3_Containment.pdf
│   ├── Section_4_Eradication_Recovery.pdf
│   └── Section_5_Post_Incident_Review.pdf
├── evidence/                      # Annotated screenshots, by section
│   └── ...
├── scripts/
│   └── health_check.sh            # Automated post-remediation verification
└── logs/                          # Raw tool output (scans, process lists, connections)
    └── ...
```

## Skills demonstrated

- Network segmentation and isolated lab design (UTM/QEMU)
- Reconnaissance and service enumeration (`nmap`, NSE scripts)
- Vulnerability research and CVE/CVSS verification against NVD
- Incident containment with evidence preservation (order of volatility)
- Linux system hardening (`inetd`, `iptables`, service minimization, `update-rc.d`)
- Bash scripting for automated security verification
- Technical documentation and incident reporting
- Disciplined, verification-first use of AI tooling
- Control framework mapping (NIST CSF 2.0, NIST SP 800-53, CIS Controls v8, ISO/IEC 27001:2022)
- Risk assessment and risk register development (likelihood/impact scoring, ownership, treatment)
- Root-cause and policy/control gap analysis
- Post-incident review per NIST SP 800-61 Rev. 2

## Lab note

This investigation was performed entirely inside an isolated virtual lab
using intentionally vulnerable training VMs. No production systems, real
organizations, or real-world targets were involved. The lab network was
later rebuilt on a properly isolated virtual network — a correction made
and documented during the investigation itself, after an initial
configuration briefly bridged the lab onto the host's own network.

## Contact

Kristopher Neumann — www.linkedin.com/in/krisneumann — krisgneumann@gmail.com
