# Phishing Email Forensics using Header Analysis + VirusTotal + MXToolbox

This well-executed email forensic investigation inspects an .eml phishing sample. In this instance, an e-mail was thrown into the processing triangle of **MXToolbox**, **VirusTotal**, and header-debugging methods to find Indicators of Compromise (IOCs), spoofing measures, and to create a realistic security operations workflow. 


# Objective 

Alongside analyzing the supposed phishing email, one would want to identify:
- Spoofed email addresses and domains
- Malicious URLs embedded within the message body
- Threat actor IP addresses
- MITRE ATT&CK mapping to phishing tactics
- Email header inconsistencies and abuse indicators

# Tools Used 

 MXToolbox -  Email header forensics and SPF/DKIM checks 
VirusTotal- URL analysis and phishing validation 
.eml file- Raw email content for analysis          

# Overview of Email Sample

- Sender: no-reply@secure-payments.com
- Reply-To: support@secure-payments.xyz
- Subject: Urgent: Confirm Your Payment Information
- Phishing URL: [http://secure-payments-update.xyz/login](http://secure-payments-update.xyz/login)
- Source IP: 198.51.100.17 (mail.spammer.net)
- .eml Sample: [phish-sample.eml](./email-header-analysis/phish-sample.eml)

# Methodology

1. Upload eml file to MXToolbox:
   - Analyzed SPF, DKIM, and header anomalies.
   - Mismatches in From: and Reply-To: headers were noticed.
   - Suspicious relay detected via IP: 198.51.100.17.

2. Inspect embedded URL in VirusTotal:
   - A suspicious link was found having a phishing site situated at secure-payments-update.xyz.
   - The URL was flagged as suspicious by Forcepoint ThreatSeeker.

3. Extracted IOCs:
   - Domain- secure-payments.xyz
   - URL- http://secure-payments-update.xyz/login
   - IP- 198.51.100.17 


# MITRE-ATT&CK Mapping

-Initial Access- Phishing: Spearphishing Link T1566.002
-Command & Control- Application Layer Protocol: Web Protocols T1071.001

# Files included

- phish-sample.eml- Raw phishing email in eml
- EM1.png to EM4.png- Screenshots for Email Header Analysis
- virustotal-url-scan-1.png- VirusTotal Phishing URL Scan Result
- mxtoolbox-header-analysis.png: MXToolbox analysis of email headers  


# Things learnt
- Email headers disclose a spoofed from identity and fake reply domains.
- Phishing URLs may bypass a few AV engines but still arise as suspicious in VirusTotal.
- - Domains like secure-payments.xyz are red flags in spearphishing attempts.
- Tools like MXToolbox and VirusTotal are critical in the SOC triage process.
- The MITRE mapping empowers clear context from attacker tactics to detection planning.




