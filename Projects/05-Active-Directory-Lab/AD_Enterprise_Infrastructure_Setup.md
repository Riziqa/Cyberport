# 🏰 Enterprise Active Directory Lab Infrastructure Setup

## Overview
Design and deployment of a multi-server Enterprise Active Directory environment using **Windows Server 2016** and **Windows 10 Enterprise** clients.

## Architecture & Configuration
* **Domain Name:** `labkernel.local`
* **Domain Controller 1 (DC1-labkernel):**
  * **OS:** Windows Server 2016
  * **IP Address:** `192.168.X.10/24`
  * **Roles:** Active Directory Domain Services (AD DS), DNS Server (Primary), DHCP Server.
* **Domain Controller 2 (DC2-labkernel):**
  * **OS:** Windows Server 2016
  * **IP Address:** `192.168.X.20/24`
  * **Roles:** Secondary Domain Controller / AD DS Replication, DNS (Secondary).
* **Client Workstations:** `win10-1` (Windows 10 Pro joined to `labkernel.local`).

## Key Implementations & Security Controls
1. **OU Hierarchy & User Management:** Structured Organizational Units (OUs) for HR, IT, Finance, and Security Teams.
2. **Group Policy Objects (GPOs):** Enforced password complexity, account lockout thresholds, restricted LAL (Local Admin Rights), and auditing policies.
3. **Network Isolation:** Host-Only subnet testing environment (`192.168.X.0/24`).
