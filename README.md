# SOC Detection Lab – Security Monitoring & Incident Analysis

## Overview
This repository contains a hands-on **Security Operations Center (SOC) Detection Lab** designed to simulate real-world attack scenarios and document how they are **detected, analyzed, and investigated** using centralized logging and SIEM techniques.

The primary objective of this lab is **defensive security** — understanding attacker behavior through logs, correlating events, and building detection logic from a SOC analyst’s perspective.

---

## Lab Objectives
- Simulate realistic attacker activity in controlled environments
- Collect and analyze logs from Windows and Linux systems
- Detect malicious behavior using SIEM (Splunk)
- Map activity to MITRE ATT&CK techniques
- Document incident timelines and indicators of compromise (IOCs)
- Strengthen SOC-level investigation and response skills

---

## Lab Architecture

### Attacker
- Kali Linux
- Tools: SSH, Impacket, xfreerdp, native Linux utilities

### Victim Systems
- Windows (Security & System Event Logs)
- Ubuntu Linux (auditd, auth.log, syslog)

### Monitoring Stack
- Splunk Enterprise
- Splunk Universal Forwarder
- Centralized log ingestion and correlation

---

## Attack Scenarios (SOC Labs)

This lab includes multiple **attack simulations**, each documented from a **detection and investigation standpoint**.

| Lab ID | SOC Lab Name | Platform | Focus Area |
|------|------------|----------|------------|
| Lab 01 | SOC Lab – Account Enumeration | Windows / Linux | Authentication Failures |
| Lab 02 | SOC Lab – Brute Force Detection | Windows / Linux | Credential Abuse |
| Lab 03 | SOC Lab – Remote Access Abuse | Windows | Lateral Movement |
| Lab 04 | SOC Lab – Unauthorized Access | Linux | SSH Misuse |
| Lab 05 | SOC Lab – Privilege Escalation | Linux | sudo Abuse |
| Lab 06 | SOC Lab – Persistence Detection | Linux | SSH Keys |
| Lab 07 | SOC Lab – Lateral Movement | Windows | WMI / SMB |
| Lab 08 | SOC Lab – Defense Evasion | Windows | Native Tools |
| Lab 09 | SOC Lab – Log Tampering | Windows / Linux | Evidence Removal |

> **Note:** Attack names are intentionally SOC-oriented to emphasize detection rather than exploitation.

---

## Documentation Structure (Per Lab)

Each SOC lab follows a consistent investigation format:

- **Attack Objective**
- **Observed Logs (Raw SIEM Output)**
- **Event Correlation**
- **Timeline of Activity**
- **Indicators of Compromise (IOCs)**
- **MITRE ATT&CK Mapping**
- **Splunk Detection Queries**
- **SOC Analysis & Conclusion**
- **Mitigation & Detection Recommendations**

This structure mirrors **real SOC incident reports**.

---

## Example Log Sources

### Windows
- Security Event Log
- System Event Log
- Event IDs:
  - 4624 / 4625 – Logon Events
  - 4688 – Process Creation
  - 1102 – Audit Log Cleared
  - 104 – System Log Cleared

### Linux
- `/var/log/auth.log`
- `/var/log/syslog`
- `/var/log/audit/audit.log`

---

## Detection & Analysis Tools
- Splunk Search Processing Language (SPL)
- Windows Event Viewer (correlation validation)
- Linux auditd
- MITRE ATT&CK Framework

---

## Skills Demonstrated
- SOC log analysis
- SIEM query development
- Incident timeline reconstruction
- Defense evasion detection
- Windows & Linux security monitoring
- Blue-team investigation mindset

---

## MITRE ATT&CK Coverage (Examples)
- T1110 – Brute Force
- T1078 – Valid Accounts
- T1021 – Remote Services
- T1059 – Command Execution
- T1070 – Indicator Removal on Host

---

## Disclaimer
This repository is created **strictly for educational and defensive security purposes**.  
All attack simulations were performed in a controlled lab environment.  
No unauthorized systems were targeted.

---

## Author
**SOC Analyst Lab Project**  
Focus: Detection Engineering, Incident Analysis, Defensive Security

---
