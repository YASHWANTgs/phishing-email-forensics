# Phishing Email Forensics using Header Analysis + VirusTotal + MXToolbox

This project demonstrates practical phishing email forensics by analyzing a suspicious `.eml` sample. The email was processed using **MXToolbox**, **VirusTotal**, and header inspection techniques to uncover Indicators of Compromise (IOCs), identify spoofing tactics, and simulate a realistic security operations workflow.


# Objective

To analyze a suspected phishing email and identify:
- Spoofed email addresses and domains
- Malicious URLs embedded in the message body
- Threat actor IP addresses
- MITRE ATT&CK mapping to phishing tactics
- Email header inconsistencies and abuse indicators

#Tools Used

| Tool              | Purpose                              |
|-------------------|---------------------------------------|
| **MXToolbox**     | Email header forensics and SPF/DKIM checks |
| **VirusTotal**    | URL analysis and phishing validation |
| **.eml file**     | Raw email content for analysis       |

# Email Sample Overview

- **Sender**: `no-reply@secure-payments.com`
- **Reply-To**: `support@secure-payments.xyz`
- **Subject**: `Urgent: Confirm Your Payment Information`
- **Phishing URL**: [http://secure-payments-update.xyz/login](http://secure-payments-update.xyz/login)
- **Source IP**: `198.51.100.17` (mail.spammer.net)
- **.eml Sample**: [`phish-sample.eml`](./email-header-analysis/phish-sample.eml)

# Methodology

1. **Upload `.eml` File** to MXToolbox:
   - Analyzed SPF, DKIM, and header anomalies.
   - Identified mismatch in `From:` and `Reply-To:` headers.
   - Detected suspicious relay via IP: `198.51.100.17`.

2. **Inspect Embedded URL via VirusTotal**:
   - Found suspicious link using phishing domain: `secure-payments-update.xyz`.
   - URL flagged as **suspicious** by **Forcepoint ThreatSeeker**.

3. **Extracted IOCs**:
   - Domain: `secure-payments.xyz`
   - URL: `http://secure-payments-update.xyz/login`
   - IP: `198.51.100.17`


#MITRE ATT&CK Mapping

| Tactic            | Technique                                 | ID           |
|-------------------|--------------------------------------------|--------------|
| Initial Access    | Phishing: Spearphishing Link               | T1566.002    |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001    |


# Files Included

| File                          | Description                           |
|-------------------------------|----------------------------------------|
| `phish-sample.eml`            | Raw phishing email in EML format       |
| `EM1.png to EM4.png`          | Screenshots of email header analysis   |
| `virustotal-url-scan-1.png`  | VirusTotal phishing URL scan result    |
| `mxtoolbox-header-analysis.png`| MXToolbox analysis of email headers |


# Things learned

- Email headers reveal spoofed sender identity and fake reply domains.
- Phishing URLs may bypass some AV engines but still appear suspicious in VirusTotal.
- Domains like `secure-payments.xyz` are red flags in spearphishing attempts.
- Tools like MXToolbox and VirusTotal are essential in SOC triage processes.
- MITRE mapping provides clear context to attackers' tactics and detection planning.



