# MITRE ATT&CK Mapping — Cloud & Identity Detection Pack v1.0

| Rule ID | Rule Name | Tactic | Technique | Severity |
|---|---|---|---|---|
| ID-001 | MFA Fatigue Attack | Credential Access | T1621 | 🔴 High |
| ID-002 | Legacy Auth Sign-In | Initial Access | T1078 | 🟡 Medium |
| ID-003 | Conditional Access Policy Modified | Defense Evasion | T1556 | 🔴 High |
| ID-004 | Privileged Role Assigned | Persistence | T1098.003 | 🔴 High |
| M365-001 | Mailbox Forwarding Rule External | Collection | T1114.003 | 🔴 High |
| M365-002 | OAuth High-Risk Permission Granted | Initial Access | T1550.001 | 🔴 High |
| M365-003 | Mass Email Deletion | Defense Evasion | T1070.008 | 🟡 Medium |
| M365-004 | External Teams Guest Added | Initial Access | T1534 | 🟢 Low |
| M365-005 | SharePoint Mass File Download | Collection | T1039 | 🟡 Medium |
| AZ-001 | Azure Subscription Role Assignment | Persistence | T1098 | 🔴 High |
| AZ-002 | Critical Azure Resource Deleted | Impact | T1485 | 🔴 High |
| AZ-003 | Key Vault Bulk Secret Access | Credential Access | T1552.001 | 🔴 High |
| SP-001 | Service Principal with High Permissions | Persistence | T1136.003 | 🔴 High |

---

## Why These Tactics Are Different From Pack 1

Pack 1 covers the **endpoint kill chain** — what happens on Windows machines after
an attacker gets in. The techniques require endpoint telemetry (MDE, Security Events).

Pack 2 covers the **cloud control plane kill chain** — what happens in your Azure AD,
M365 tenant, and Azure subscription. These attacks leave NO trace on endpoints because
they happen entirely in cloud APIs.

**Example attack chain that only Pack 2 detects:**

1. Attacker sends consent phishing email → user approves OAuth app (M365-002)
2. App reads all emails silently → attacker finds credentials in email (M365-001 style)
3. Attacker signs in via legacy auth, bypassing MFA (ID-002)
4. Attacker assigns themselves Global Admin role (ID-004)
5. Attacker disables Conditional Access policies (ID-003)
6. Attacker creates a backdoor service principal (SP-001)
7. Attacker bulk-reads Key Vault secrets (AZ-003)
8. Attacker downloads all SharePoint files (M365-005)

None of these steps touch a Windows endpoint. Pack 1 would be completely blind to this
entire attack chain. Pack 2 covers every step.
