# ☁️ Microsoft Sentinel Cloud & Identity Detection Pack for SMEs — v1.0

> **20 production-ready KQL detection rules** for cloud-native attacks against Azure AD, Microsoft 365, and Azure resources.
> The companion pack to the [Endpoint & Network Detection Pack](https://github.com/ismaelggm1/sentinel-sme-detection-pack).

---

## Why This Pack Exists

Most SME Sentinel deployments focus on endpoint detection. But the majority of modern
attacks against SMEs never touch an endpoint at all — they happen entirely in the cloud:

- A user approves a malicious OAuth app → attacker reads all emails forever
- An attacker uses legacy auth to bypass MFA → no endpoint alert fires
- A compromised admin disables Conditional Access → the attacker locks you out
- A rogue service principal silently reads Key Vault secrets → complete credential dump

**Pack 1 (Endpoint) is completely blind to these attacks. This pack covers them.**

---

## What's Inside

| Category | Rules | Key Threats |
|---|---|---|
| Identity Attacks | 4 | MFA fatigue, legacy auth bypass, CAP tampering, role abuse |
| Azure Resource Abuse | 3 | Subscription role assignment, resource deletion, runbook abuse |
| Microsoft 365 | 5 | Mail forwarding, OAuth phishing, mass deletion, Teams guest, SharePoint exfil |
| Azure Storage & Key Vault | 3 | Key Vault secret dump, storage exposure, SAS token abuse |
| Service Principal Abuse | 3 | Rogue SPs, credential add, SP from new location |

Every rule includes MITRE ATT&CK mapping, configuration block, tuning notes, and response steps.

---

## Pack 1 vs Pack 2 — Which Do You Need?

| | Pack 1 — Endpoint & Network | Pack 2 — Cloud & Identity |
|---|---|---|
| **What it monitors** | Windows machines | Azure AD, M365, Azure |
| **Data sources** | MDE, Security Events | AuditLogs, AzureActivity, OfficeActivity |
| **Attack surface** | Malware, lateral movement | Account takeover, cloud privilege escalation |
| **Best for** | On-prem / hybrid environments | Cloud-first / M365-heavy orgs |
| **Answer** | ✅ Get both | ✅ Get both |

Most attacks start with cloud credential compromise (Pack 2 detects this), then move to
endpoints (Pack 1 detects this). You need both for complete coverage.

---

## 🆓 Free Sample Rules

### SAMPLE 1 — MFA Fatigue Attack
**MITRE:** T1621 | **Severity:** 🔴 High

```kql
// Detects repeated MFA denial — attacker flooding user with push notifications
// hoping they approve. Technique that compromised Uber, Cisco, and many SMEs.

let MFADenialThreshold = 5;

SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| where ResultDescription has_any ("MFA denied", "user did not pass the MFA challenge")
| summarize
    MFADenials = count(),
    SourceIPs = make_set(IPAddress),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by UserPrincipalName
| where MFADenials >= MFADenialThreshold
```

> **Response:** Contact user immediately. Enable MFA number matching in Authenticator. Check for successful login after denials.

---

### SAMPLE 2 — Mailbox Forwarding Rule to External Address
**MITRE:** T1114.003 | **Severity:** 🔴 High

```kql
// #1 post-compromise action after M365 account takeover.
// Silent forwarding for intelligence gathering or BEC preparation.

let InternalDomain = "yourdomain.com";

OfficeActivity
| where TimeGenerated > ago(1h)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where tostring(Parameters) has_any ("ForwardTo", "RedirectTo")
| where not (tostring(Parameters) has InternalDomain)
| project TimeGenerated, UserId, ClientIP, Parameters
```

> **Response:** Delete the rule immediately. Assess what may have been forwarded. Check for BEC activity.

---

### SAMPLE 3 — Conditional Access Policy Disabled
**MITRE:** T1556 | **Severity:** 🔴 High

```kql
// Attacker with Global Admin will disable CAPs to enable persistent access.
// Any unauthorized CAP change = treat as critical.

AuditLogs
| where TimeGenerated > ago(1h)
| where Category == "Policy"
| where OperationName in ("Delete conditional access policy", "Update conditional access policy")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, Actor, OperationName,
    PolicyName = tostring(TargetResources[0].displayName)
```

---

## 💰 Full Pack — 20 Rules + Docs

**[→ Buy on Gumroad](https://gumroad.com)** — €39

Includes all 20 rules + MITRE mapping + deployment guide + connector setup + response playbooks.

**Bundle both packs (43 rules total): €59**

---

## 👤 About the Author

Cybersecurity professional with hands-on SOC, IR, and SIEM engineering experience at **Microsoft** and **Capgemini**. Certified: CompTIA Security+, Google Cybersecurity Professional.

🔗 [LinkedIn](https://www.linkedin.com/in/ismaelgaton-32651a238/) | 📧 ismaelgatongg@gmail.com

---

## ⚠️ Disclaimer

For defensive security purposes only. Test in non-production environments before deploying.

