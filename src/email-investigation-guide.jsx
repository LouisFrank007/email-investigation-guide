import { useState } from "react";

const COLORS = {
  bg: "#0a0e1a", surface: "#111827", surfaceAlt: "#1a2235",
  border: "#1e2d45", accent: "#00d4ff", accentDim: "#0099bb",
  danger: "#ff4757", warn: "#ffb300", success: "#00e676",
  textPrimary: "#e8f0fe", textSecondary: "#8899bb", textMuted: "#4a5a7a",
  critical: "#ff3860", high: "#ff6b35", medium: "#ffb300", low: "#00e676",
  purple: "#a78bfa", green2: "#34d399",
};

const severityColor = (s) => ({ CRITICAL: COLORS.critical, HIGH: COLORS.high, MEDIUM: COLORS.medium, LOW: COLORS.low }[s] || COLORS.textSecondary);

// ─── CHECKLIST DATA with WHERE ────────────────────────────────────────────────

const CHECKLIST_SECTIONS = [
  {
    id: "triage",
    title: "Initial Triage",
    icon: "🔍",
    items: [
      {
        task: "Retrieve original email in .eml format",
        where: "M365: Security Portal → Email & Collaboration → Explorer → find email → Download\nGoogle Workspace: Admin Console → Reports → Email Log Search → Export\nProofpoint: Administration → Message Center → Search → Export\nMimecast: Administration Console → Gateway → Message Center",
        cmd: null,
      },
      {
        task: "Record: sender, recipient, subject, timestamp, Message-ID",
        where: "View raw email headers:\nGmail: ⋮ → Show original\nOutlook: File → Properties → Internet headers\nApple Mail: View → Message → All Headers\nThunderbird: View → Headers → All",
        cmd: null,
      },
      {
        task: "Check if other users received the same email",
        where: "M365 Defender: security.microsoft.com → Email & Collaboration → Explorer → search by Subject or Sender\nGoogle Workspace: admin.google.com → Reports → Audit → Email Log Search\nProofpoint: Message Center → search sender/subject across org\nMimecast: Gateway → Message Center → search by sender",
        cmd: null,
      },
      {
        task: "Check if anyone opened, clicked, or replied",
        where: "M365 Defender: Explorer → select email → Email timeline tab\nGoogle Workspace: Admin → Reports → Email Log → click message ID → view delivery details\nProofpoint: TAP Dashboard → threat detail → click activity\nMimecast: Message Center → click message → Message Info → Events tab",
        cmd: null,
      },
      {
        task: "Assign severity and open incident ticket",
        where: "Ticketing: ServiceNow / Jira / TheHive / PagerDuty\nInternal escalation matrix: see your runbook\nSLA: CRITICAL=15min, HIGH=1hr, MEDIUM=4hr, LOW=24hr",
        cmd: null,
      },
    ],
  },
  {
    id: "headers",
    title: "Header Analysis",
    icon: "📋",
    items: [
      {
        task: "Extract full Received header chain (read bottom → top)",
        where: "Paste raw headers into:\n→ Google Admin Toolbox: toolbox.googleapps.com/apps/messageheader\n→ MXToolbox: mxtoolbox.com/EmailHeaders.aspx\n→ Mail Header Analyzer: mailheader.org",
        cmd: null,
      },
      {
        task: "Identify originating IP from bottom-most Received header",
        where: "Look for: 'Received: from [hostname] ([IP])'\nBottom-most entry = first server that touched the email = true origin\nIgnore internal relay IPs (10.x, 172.16.x, 192.168.x)",
        cmd: null,
      },
      {
        task: "Run originating IP through WHOIS",
        where: "→ whois.domaintools.com\n→ who.is\n→ arin.net/search (Americas)\n→ ripe.net/search (Europe)\n→ apnic.net (Asia-Pacific)",
        cmd: "whois 1.2.3.4",
      },
      {
        task: "Run IP through GeoIP lookup",
        where: "→ ipinfo.io/1.2.3.4\n→ ip-api.com/1.2.3.4\n→ maxmind.com/en/geoip-demo\n→ VirusTotal: virustotal.com/gui/ip-address/1.2.3.4",
        cmd: null,
      },
      {
        task: "Check IP on blacklists",
        where: "→ MXToolbox Blacklist: mxtoolbox.com/blacklists.aspx\n→ AbuseIPDB: abuseipdb.com/check/1.2.3.4\n→ Spamhaus: spamhaus.org/lookup\n→ Talos Intelligence: talosintelligence.com/reputation_center",
        cmd: "nslookup -q=txt 4.3.2.1.zen.spamhaus.org",
      },
      {
        task: "Verify SPF result",
        where: "Check Authentication-Results header in raw email for: spf=pass / fail / softfail / neutral\nVerify domain SPF record:\n→ MXToolbox: mxtoolbox.com/spf.aspx\n→ dmarcanalyzer.com/spf/spf-check",
        cmd: "nslookup -q=txt yourdomain.com",
      },
      {
        task: "Verify DKIM result",
        where: "Check Authentication-Results header for: dkim=pass / fail / none\nVerify DKIM record exists:\n→ MXToolbox: mxtoolbox.com/dkim.aspx\n→ easydmarc.com/tools/dkim-lookup",
        cmd: null,
      },
      {
        task: "Verify DMARC result",
        where: "Check Authentication-Results header for: dmarc=pass / fail / none\nCheck domain DMARC policy:\n→ MXToolbox: mxtoolbox.com/dmarc.aspx\n→ dmarcanalyzer.com\n→ easydmarc.com/tools/dmarc-lookup",
        cmd: "nslookup -q=txt _dmarc.yourdomain.com",
      },
      {
        task: "Compare From vs Return-Path vs Reply-To",
        where: "All visible in raw email headers\nRed flags:\n• Reply-To differs from From → likely phishing\n• Return-Path domain ≠ From domain → spoofing indicator\n• Display name says 'Microsoft' but From is random@evil.com",
        cmd: null,
      },
      {
        task: "Check if Message-ID domain matches sender domain",
        where: "Message-ID format: <random@sending-domain.com>\nDomain after @ should match the From domain\nMismatch = forged header indicator",
        cmd: null,
      },
    ],
  },
  {
    id: "urls",
    title: "URL & Link Analysis",
    icon: "🔗",
    items: [
      {
        task: "Extract all URLs from email body",
        where: "View raw source of email (.eml file) in text editor\nM365 Defender: Explorer → select email → URLs tab (lists all embedded links)\nProofpoint: Message details → URL Defense tab\nMimecast: Message Info → URLs section",
        cmd: 'grep -oP \'https?://[^\\s"<>]+\' email.eml',
      },
      {
        task: "Defang all URLs before sharing or documenting",
        where: "Manual: replace http with hxxp and . with [.]\nExample: https://evil.com → hxxps://evil[.]com\nTool: → cyberchef.org → 'Defang URL' operation",
        cmd: null,
      },
      {
        task: "Check each URL on VirusTotal",
        where: "→ virustotal.com/gui/home/url — paste URL, scan\nAPI: curl -X POST 'https://www.virustotal.com/api/v3/urls' \\\n  -H 'x-apikey: YOUR_KEY' -d 'url=https://evil.com'\nLook for: vendor detections, community score, categories",
        cmd: null,
      },
      {
        task: "Check each URL on URLScan.io",
        where: "→ urlscan.io — paste URL → submit for full scan\nShows: screenshot, DOM, redirects, IPs contacted, certificates\nSearch existing scans: urlscan.io/search/#domain:evil.com",
        cmd: null,
      },
      {
        task: "Check URL against phishing databases",
        where: "→ PhishTank: phishtank.org/check.php\n→ OpenPhish: openphish.com/phishing_feeds.html\n→ Google Safe Browsing: transparencyreport.google.com/safe-browsing/search",
        cmd: null,
      },
      {
        task: "Trace full redirect chain",
        where: "→ redirect-checker.org\n→ urlix.me\n→ wheregoes.com\nDo NOT manually click — use these tools in browser isolation",
        cmd: "curl -sI -L 'https://short.url/abc' | grep -i location",
      },
      {
        task: "Check domain registration date and registrar",
        where: "→ whois.domaintools.com\n→ who.is\n→ icann.org/lookup\nRed flag: domain registered < 30 days ago\nRed flag: privacy-protected registrant on a 'corporate' sender",
        cmd: "whois evil.com | grep -i 'creation date'",
      },
      {
        task: "Check for lookalike / typosquatting domain",
        where: "→ dnstwist.it — enter legitimate domain, see all possible typosquats\n→ URLCrazy (command line tool)\n→ Manually compare: paypa1.com vs paypal.com, arnazon.com vs amazon.com",
        cmd: "dnstwist --registered paypal.com",
      },
      {
        task: "Capture landing page in sandboxed browser",
        where: "→ any.run — interactive sandbox with live browser\n→ browserling.com — test URL in isolated browser\n→ urlscan.io — screenshots full page render\n→ app.any.run — full behavioral capture",
        cmd: null,
      },
      {
        task: "Check click events — who clicked and when",
        where: "M365 Defender: security.microsoft.com → Email & Collaboration → Explorer → select email → URL clicks tab\nProofpoint: TAP Dashboard → Clicks → search by recipient\nMimecast: Targeted Threat Protection → URL Protect → Logs\nGoogle Workspace: Admin → Security → Alert Center",
        cmd: null,
      },
    ],
  },
  {
    id: "attachments",
    title: "Attachment Analysis",
    icon: "📎",
    items: [
      {
        task: "Save attachment to isolated VM — NEVER open on production machine",
        where: "Options for isolation:\n→ Any.run: app.any.run (upload file, full sandbox)\n→ Hybrid Analysis: hybrid-analysis.com\n→ VMware / VirtualBox local VM (network disabled)\n→ FlareVM: dedicated malware analysis OS",
        cmd: null,
      },
      {
        task: "Hash the attachment immediately (SHA-256)",
        where: "Windows: Get-FileHash file.exe -Algorithm SHA256\nLinux/Mac: sha256sum file.exe\nOnline: virustotal.com (auto-hashes on upload)",
        cmd: "sha256sum suspicious_file.pdf\nGet-FileHash .\\file.exe -Algorithm SHA256",
      },
      {
        task: "Check file hash on VirusTotal",
        where: "→ virustotal.com/gui/home/search — paste SHA256 hash\nIf hash known: instant result with 70+ AV verdicts\nIf unknown: upload file for first-time scan\nAlso check: Malware Bazaar → bazaar.abuse.ch/browse",
        cmd: null,
      },
      {
        task: "Extract file metadata",
        where: "Tool: ExifTool (exiftool.org)\nInstall: brew install exiftool / apt install libimage-exiftool-perl\nKey fields: Author, Creator, LastModifiedBy, Software, CreateDate",
        cmd: "exiftool suspicious.pdf\nexiftool -json suspicious.docx",
      },
      {
        task: "Submit to sandbox for behavioral analysis",
        where: "→ Any.run: app.any.run — interactive, real-time, free tier available\n→ Hybrid Analysis: hybrid-analysis.com — automated, free\n→ Joe Sandbox: joesandbox.com\n→ Cuckoo: self-hosted open-source sandbox\nLook for: process tree, network connections, registry changes, dropped files",
        cmd: null,
      },
      {
        task: "For PDFs: analyze structure for malicious elements",
        where: "Tool: pdfid.py + pdf-parser.py (Didier Stevens tools)\nDownload: didierstevens.com/files/software\nRed flags: /JavaScript /OpenAction /Launch /EmbeddedFile /AcroForm",
        cmd: "python pdfid.py suspicious.pdf\npython pdf-parser.py --search /JavaScript suspicious.pdf",
      },
      {
        task: "For Office files: detect macros and suspicious content",
        where: "Tool: oletools (github.com/decalage2/oletools)\nInstall: pip install oletools\nolevba: extracts and analyzes VBA macros\noledump: lists streams in OLE files\nmraptor: detects malicious macro patterns",
        cmd: "olevba suspicious.docm\noledump.py suspicious.xls\nmraptor suspicious.pptm",
      },
      {
        task: "For executables: static analysis before running",
        where: "→ PEStudio: winitor.com — PE file static analysis, free\n→ Detect-It-Easy (DIE): detects packers/compilers\n→ Strings analysis: extract readable strings\n→ VirusTotal: check imports, sections, overlay",
        cmd: "strings -n 8 malware.exe | grep -i 'http\\|cmd\\|powershell'\npestudio malware.exe",
      },
      {
        task: "For archives (.zip/.rar): extract safely in sandbox",
        where: "Extract in isolated VM only\nTool: 7-Zip for extraction\nPassword-protected zip: password is usually in the email body\nAfter extraction: analyze each file individually with above steps",
        cmd: "7z l suspicious.zip\n7z x suspicious.zip -o./extracted/",
      },
      {
        task: "Block file hash at EDR level org-wide",
        where: "CrowdStrike Falcon: falcon.crowdstrike.com → Prevention Hashes → Add Hash → Block\nSentinelOne: Management → Blacklist → Add SHA256\nMicrosoft Defender ATP: security.microsoft.com → Indicators → File → Add\nCarbon Black: Enforce → Banned Hashes",
        cmd: null,
      },
    ],
  },
  {
    id: "events",
    title: "Email Events & Logs",
    icon: "📊",
    items: [
      {
        task: "View full email delivery event timeline",
        where: "M365 Defender: security.microsoft.com → Email & Collaboration → Explorer → select message → Email timeline\nGoogle Workspace: admin.google.com → Reporting → Email Log Search → click Message ID\nProofpoint: Message Center → select message → Message Detail → Events tab\nMimecast: Administration → Gateway → Message Center → search → Message Info",
        cmd: null,
      },
      {
        task: "Check gateway delivery verdict (allow / quarantine / block)",
        where: "M365: security.microsoft.com → Email & Collaboration → Review → Quarantine\nProofpoint: Administration → Message Center → filter by Action\nMimecast: Gateway → Held Messages / Rejected Messages\nBarracuda: Message Log → filter by Action\nGoogle: Admin → Reports → Email Log Search → Delivery Status",
        cmd: null,
      },
      {
        task: "Search for all emails from same sender org-wide",
        where: "M365: security.microsoft.com → Explorer → Sender field → search\nGoogle: Admin → Email Log Search → From field\nProofpoint: Message Center → Sender field → search all recipients\nExchange on-prem: Get-MessageTrackingLog -Sender attacker@evil.com",
        cmd: 'Get-MessageTrackingLog -Sender "attacker@evil.com" -Start (Get-Date).AddDays(-7) | Select Sender,Recipients,MessageSubject,Timestamp',
      },
      {
        task: "Check if email was forwarded externally",
        where: "M365: security.microsoft.com → Policies → Anti-spam → Outbound\nExchange: Get-InboxRule | Where {$_.ForwardTo -ne $null}\nGoogle: Admin → Users → select user → Gmail settings → Forwarding\nAlso check: SIEM for outbound SMTP to external domains",
        cmd: "Get-InboxRule -Mailbox victim@company.com | Select Name,ForwardTo,ForwardAsAttachmentTo | Where {$_.ForwardTo -ne $null}",
      },
      {
        task: "Review outbound email activity for data exfiltration",
        where: "M365: security.microsoft.com → Explorer → filter Outbound direction → check attachments\nGoogle: Admin → Email Log Search → Direction = Outgoing\nDLP Logs: Microsoft Purview / Google DLP / Proofpoint DLP → search by user\nSIEM: search for large outbound email volume or unusual recipients",
        cmd: null,
      },
      {
        task: "Check mail flow rules / transport rules for manipulation",
        where: "M365 Exchange Admin: admin.exchange.microsoft.com → Mail flow → Rules\nGoogle: Admin → Apps → Google Workspace → Gmail → Routing\nProofpoint: Email Firewall → Rules\nCheck for: rules that delete, forward, or modify messages silently",
        cmd: "Get-TransportRule | Select Name,State,Priority,Description | Format-List",
      },
      {
        task: "Review inbox rules on compromised / targeted account",
        where: "M365: Microsoft 365 Admin → Users → select user → Mail settings → Inbox rules\nOWA: outlook.office.com → Settings → View all → Rules\nPowerShell: Get-InboxRule -Mailbox user@company.com\nGoogle: Admin → Users → select user → Gmail → Filters\nRed flags: rules that delete/archive/forward emails silently",
        cmd: "Get-InboxRule -Mailbox victim@company.com | Select Name,Enabled,Conditions,Actions | Format-List",
      },
      {
        task: "Check SMTP authentication logs for unauthorized sending",
        where: "M365: admin.microsoft.com → Reports → Usage → Email activity\nExchange: Get-MessageTrackingLog -EventId SEND\nGoogle: Admin → Reports → Audit → Login Audit\nSIEM: search for SMTP AUTH events from unusual IPs",
        cmd: "Get-MessageTrackingLog -EventId SEND -Sender victim@company.com -Start (Get-Date).AddDays(-3)",
      },
    ],
  },
  {
    id: "containment",
    title: "Containment",
    icon: "🛡️",
    items: [
      {
        task: "Bulk quarantine / purge email from all mailboxes",
        where: "M365 Defender: security.microsoft.com → Explorer → select messages → Remediate → Soft/Hard delete\nExchange Online PowerShell: Search-Mailbox + Delete\nGoogle Workspace: Admin → Reports → Email Log → select messages → Delete\nProofpoint: Message Center → select → Quarantine or Recall",
        cmd: '$search = New-ComplianceSearch -Name "RemovePhish" -ExchangeLocation All -ContentMatchQuery \'Subject:"Urgent Invoice" AND From:"attacker@evil.com"\'\nStart-ComplianceSearch -Identity "RemovePhish"\nNew-ComplianceSearchAction -SearchName "RemovePhish" -Purge -PurgeType HardDelete',
      },
      {
        task: "Block sender email address at gateway",
        where: "M365: security.microsoft.com → Policies → Tenant Allow/Block List → Emails → Block\nExchange: New-TransportRule -SenderAddressLocation Header -From attacker@evil.com -RejectMessageReasonText 'Blocked'\nProofpoint: Email Firewall → Blocklist → add sender\nMimecast: Gateway → Definitions → Blocked Senders",
        cmd: "New-TenantAllowBlockListItems -ListType Sender -Block -Entries 'attacker@evil.com' -NoExpiration",
      },
      {
        task: "Block sender domain at gateway",
        where: "M365: security.microsoft.com → Policies → Tenant Allow/Block List → Domains → Block\nExchange Admin: Anti-spam → Connection filter → Block list\nProofpoint: Email Firewall → Blocklist → add domain\nMimecast: Gateway → Definitions → Blocked Senders → add @evil.com",
        cmd: "New-TenantAllowBlockListItems -ListType Sender -Block -Entries '*@evil.com' -NoExpiration",
      },
      {
        task: "Block originating IP at firewall / email gateway",
        where: "Palo Alto: Policies → Security → add deny rule for source IP\nFortigate: Policy & Objects → Addresses → create IP object → add to deny policy\nM365: security.microsoft.com → Policies → Anti-spam → Connection filter → IP Block list\nProofpoint: Administration → Account Management → Spam Detection → IP Reputation",
        cmd: null,
      },
      {
        task: "Block malicious URLs at DNS / proxy level",
        where: "Cisco Umbrella: dashboard.umbrella.com → Policies → Destination Lists → add domain\nZscaler: policy.zscaler.com → URL & Cloud App Control → Custom Categories → Block\nPalo Alto DNS Security: add to custom block list\nPi-hole (internal): Settings → Blacklist → add domain\nM365 Defender: security.microsoft.com → Indicators → URL → Block",
        cmd: null,
      },
      {
        task: "Block file hash at EDR",
        where: "CrowdStrike: falcon.crowdstrike.com → Prevention Hashes → Add Hash → Never Allowed\nSentinelOne: Sentinels → Blacklist → Add SHA256\nMicrosoft Defender: security.microsoft.com → Settings → Endpoints → Indicators → File hashes\nCarbon Black: Enforce → Banned Hashes → Add",
        cmd: null,
      },
      {
        task: "Isolate affected device from network",
        where: "CrowdStrike: Falcon → Host Management → find device → Contain\nSentinelOne: Endpoints → select device → Actions → Network Quarantine\nMicrosoft Defender: security.microsoft.com → Devices → select → Isolate device\nCarbon Black: Devices → select → Quarantine\nDO NOT power off — preserves volatile memory",
        cmd: null,
      },
      {
        task: "Force password reset on compromised / at-risk account",
        where: "M365: admin.microsoft.com → Users → Active users → select user → Reset password\nAzure AD: portal.azure.com → Azure Active Directory → Users → Reset password\nGoogle: admin.google.com → Users → select user → Reset password\nActive Directory: ADUC → right-click user → Reset Password\nAlso: Revoke all refresh tokens",
        cmd: "Set-MsolUserPassword -UserPrincipalName victim@company.com -ForceChangePassword $true\nRevoke-AzureADUserAllRefreshToken -ObjectId <user-object-id>",
      },
      {
        task: "Revoke active sessions and OAuth tokens",
        where: "M365/Azure AD: portal.azure.com → Azure AD → Users → select → Revoke sessions\nGoogle: admin.google.com → Users → select → Security → Sign out of all sessions\nOkta: Admin → Users → select → More Actions → Sign Out All\nAzure PowerShell: Revoke-AzureADUserAllRefreshToken",
        cmd: "Revoke-AzureADUserAllRefreshToken -ObjectId <ObjectId>\nRevoke-MsolUserAllRefreshToken -UserPrincipalName victim@company.com",
      },
    ],
  },
  {
    id: "accountcheck",
    title: "Account Compromise Check",
    icon: "👤",
    items: [
      {
        task: "Review sign-in history for unusual logins",
        where: "Azure AD: portal.azure.com → Azure Active Directory → Users → select → Sign-in logs\nM365: admin.microsoft.com → Reports → Usage → Sign-ins\nGoogle: admin.google.com → Reports → Audit → Login\nOkta: Reports → System Log → filter by actor\nLook for: new countries, odd hours, unknown devices, failed then success",
        cmd: "Get-AzureADAuditSignInLogs -Filter \"userPrincipalName eq 'victim@company.com'\" | Select CreatedDateTime,IpAddress,Location,Status | Sort CreatedDateTime -Descending | Select -First 50",
      },
      {
        task: "Check for new inbox rules (forward / delete / move)",
        where: "M365 OWA: outlook.office.com → Settings → View all Outlook settings → Rules\nExchange PowerShell: Get-InboxRule -Mailbox user@company.com\nGoogle: Admin → Users → Gmail settings → Filters\nRed flags: rules forwarding to external addresses, auto-deleting security emails",
        cmd: "Get-InboxRule -Mailbox victim@company.com | Where {$_.ForwardTo -ne $null -or $_.DeleteMessage -eq $true -or $_.ForwardAsAttachmentTo -ne $null}",
      },
      {
        task: "Check for new OAuth app grants / connected apps",
        where: "M365: portal.azure.com → Enterprise Applications → filter by recent consent\nM365 Admin: admin.microsoft.com → Settings → Integrated apps\nGoogle: admin.google.com → Security → API Controls → App Access Control\nOkta: Applications → filter by created date\nLook for: unfamiliar apps with Mail.Read or Mail.Send permissions",
        cmd: "Get-AzureADServicePrincipal -All $true | Where {$_.AppOwnerTenantId -ne '<your-tenant-id>'} | Select DisplayName,AppId,ReplyUrls",
      },
      {
        task: "Review sent items for emails the user didn't send",
        where: "OWA: outlook.office.com → Sent Items → sort by date\nExchange PowerShell: Get-MessageTrackingLog -Sender user@company.com\nGoogle: Gmail → Sent → sort by date\nLook for: phishing sent to contacts, password reset requests, financial requests",
        cmd: "Get-MessageTrackingLog -Sender victim@company.com -Start (Get-Date).AddDays(-7) -EventId SEND | Select Timestamp,Recipients,MessageSubject",
      },
      {
        task: "Check for new email delegates or shared mailbox access",
        where: "Exchange: Get-MailboxPermission / Get-RecipientPermission\nM365 Admin: Exchange Admin Center → Mailboxes → select user → Mailbox delegation\nGoogle: Admin → Users → select → Gmail settings → Delegation",
        cmd: "Get-MailboxPermission -Identity victim@company.com | Where {$_.User -notlike 'NT AUTHORITY*'}\nGet-RecipientPermission victim@company.com | Where {$_.Trustee -notlike 'NT AUTHORITY*'}",
      },
      {
        task: "Check SIEM for lateral movement after email compromise",
        where: "Splunk: index=windows EventCode=4624 OR EventCode=4648 | search AccountName=victim\nMicrosoft Sentinel: SecurityEvent | where Account == 'victim' | summarize by Activity\nQRadar: search for authentication events from compromised account\nLook for: new RDP connections, new SMB access, new service accounts",
        cmd: 'index=windows EventCode=4624 AccountName="victim_user" | stats count by IpAddress, LogonType | sort -count',
      },
      {
        task: "Check Have I Been Pwned for email exposure",
        where: "→ haveibeenpwned.com — enter email address\n→ API: api.pwnedpasswords.com\nShows: which breaches the email appeared in and what data was exposed\nIf found in breach: immediate credential reset required",
        cmd: "curl 'https://haveibeenpwned.com/api/v3/breachedaccount/victim@company.com' -H 'hibp-api-key: YOUR_KEY'",
      },
    ],
  },
  {
    id: "evidence",
    title: "Evidence & Documentation",
    icon: "📁",
    items: [
      {
        task: "Export original email as .eml with full headers",
        where: "M365 Defender: Explorer → select email → Download (exports .eml)\nGmail: ⋮ → Download message (.eml)\nOutlook: File → Save As → Outlook Message Format (.msg) or use ExportEML add-in\nThunderbird: File → Save As → File (.eml)\nProofpoint: Message Center → Download Original",
        cmd: null,
      },
      {
        task: "SHA-256 hash all evidence files",
        where: "Windows PowerShell: Get-FileHash\nLinux/Mac Terminal: sha256sum\nRecord hash immediately — proves file was not modified after collection\nStore hash alongside file in evidence log",
        cmd: "sha256sum evidence_email.eml\nGet-FileHash .\\evidence_email.eml -Algorithm SHA256 | Select Hash",
      },
      {
        task: "Export email gateway logs for incident timeframe",
        where: "M365: security.microsoft.com → Email & Collaboration → Explorer → Export\nProofpoint: Message Center → Export to CSV\nMimecast: Message Center → Export\nGoogle: Admin → Email Log Search → Export\nExchange PowerShell: Get-MessageTrackingLog → Export-CSV",
        cmd: "Get-MessageTrackingLog -Start '2026-06-09 08:00' -End '2026-06-09 12:00' | Export-CSV -Path C:\\Logs\\mail_log.csv -NoTypeInformation",
      },
      {
        task: "Export SIEM logs for incident timeframe",
        where: "Splunk: Search → time range → Export → CSV/JSON\nMicrosoft Sentinel: Logs → run KQL query → Export\nQRadar: Log Activity → filter → Export to CSV\nElastic: Kibana → Discover → filter → Export\nCapture: all events ±2 hours around incident",
        cmd: null,
      },
      {
        task: "Screenshot all key investigation findings",
        where: "Capture: VirusTotal results, URLScan screenshots, sandbox reports, header analysis, login anomalies\nTool: OS screenshot + annotate with Greenshot, Snagit, or built-in\nStore in incident folder with sequential naming: INC-2026-001_VT_result.png",
        cmd: null,
      },
      {
        task: "Document chain of custody",
        where: "Log every evidence item:\n• What: file name + hash\n• When: exact collection timestamp (UTC)\n• Who: analyst name\n• Where stored: path / share\n• Who accessed: access log\nUse your case management system: TheHive / ServiceNow / Jira",
        cmd: null,
      },
      {
        task: "Submit IOCs to threat intel platform",
        where: "MISP: your-misp-instance → Events → Add Event → add attributes\nOpenCTI: your-opencti-instance → Create Indicators\nTheHive + Cortex: auto-analyzes and tags IOCs\nVirusTotal Graph: visualize IOC relationships\nISAC sharing: FS-ISAC, H-ISAC depending on your sector",
        cmd: null,
      },
    ],
  },
  {
    id: "closure",
    title: "Closure & Reporting",
    icon: "✅",
    items: [
      {
        task: "Notify affected users with clear non-technical guidance",
        where: "Send via secure channel (Teams/Slack/phone — NOT email if account compromised)\nInclude: what happened, what they need to do, who to contact\nFor VIPs: personal call from IR lead or CISO",
        cmd: null,
      },
      {
        task: "Tune email gateway rules based on findings",
        where: "M365: security.microsoft.com → Policies → Anti-phishing / Anti-spam → update rules\nProofpoint: Email Firewall → add new rule based on attack pattern\nMimecast: Gateway → Policies → create targeted rule\nDocument: what rule was added and why, for audit trail",
        cmd: null,
      },
      {
        task: "Update EDR detection rules / custom IOCs",
        where: "CrowdStrike: Custom IOA Rules → add behavioral detection\nSentinelOne: Exclusions & Blacklists → add new entries\nMicrosoft Defender: Custom Detection Rules → create KQL-based rule\nCarbon Black: Watchlists → add new threat indicators",
        cmd: null,
      },
      {
        task: "Update DNS / proxy block lists",
        where: "Cisco Umbrella: Policies → Destination Lists → add new domains\nZscaler: URL Filtering → Custom Categories → add domains\nPalo Alto: Security Profiles → URL Filtering → Block List\nInternal DNS: add NXDOMAIN responses for C2 domains",
        cmd: null,
      },
      {
        task: "File external report if required",
        where: "Financial loss (BEC/fraud): FBI IC3 → ic3.gov\nData breach (GDPR): national DPA within 72 hours\nData breach (HIPAA): HHS OCR → hhs.gov/hipaa\nCyber insurance: notify provider per policy terms\nSector ISAC: share anonymized TTPs with peers",
        cmd: null,
      },
      {
        task: "Conduct post-incident review and update playbook",
        where: "Schedule within 72 hours of closure\nAttendees: SOC lead, IR analyst, affected team manager\nAgenda: timeline, gaps identified, what worked, what to improve\nOutput: updated playbook, new detection rules, training topics",
        cmd: null,
      },
      {
        task: "Close incident ticket with full documentation",
        where: "ServiceNow / Jira / TheHive: update ticket with:\n• Final timeline\n• All IOCs\n• Actions taken\n• Root cause\n• Recommendations\n• Lessons learned\nChange status to Resolved → Closed",
        cmd: null,
      },
    ],
  },
];

// ─── DECISION TREE DATA ───────────────────────────────────────────────────────

const DECISION_TREE = {
  id: "root",
  q: "What type of email incident are you investigating?",
  options: [
    {
      label: "Suspicious / Phishing Email",
      next: {
        id: "phish1", q: "Has any user interacted with the email?",
        options: [
          {
            label: "No — email just delivered",
            next: {
              id: "phish_noclick", result: true, severity: "MEDIUM",
              type: "Phishing — No Interaction",
              steps: [
                { task: "Retrieve email from quarantine", where: "M365 Defender: security.microsoft.com → Email & Collaboration → Review → Quarantine\nProofpoint: Administration → Message Center\nMimecast: Gateway → Held Messages" },
                { task: "Full header analysis — check SPF / DKIM / DMARC", where: "Paste headers into: toolbox.googleapps.com/apps/messageheader\nOR: mxtoolbox.com/EmailHeaders.aspx" },
                { task: "Extract and defang all URLs", where: "M365 Defender: Explorer → select message → URLs tab\nManual: view raw .eml source\nDefang at: cyberchef.org → Defang URL" },
                { task: "Submit URLs to threat intelligence", where: "→ virustotal.com/gui/home/url\n→ urlscan.io\n→ phishtank.org/check.php" },
                { task: "Hash attachments and check reputation", where: "Hash: sha256sum file.ext (Linux) or Get-FileHash (PowerShell)\nCheck: virustotal.com/gui/home/search (paste hash)\nCheck: bazaar.abuse.ch" },
                { task: "Search gateway for same email org-wide", where: "M365: security.microsoft.com → Explorer → search by sender/subject\nExchange PS: Get-MessageTrackingLog -Sender attacker@evil.com" },
                { task: "Bulk quarantine from all mailboxes", where: "M365 PowerShell: New-ComplianceSearch → New-ComplianceSearchAction -Purge\nM365 UI: Explorer → Remediate → Soft Delete" },
                { task: "Block sender / domain / IPs / URLs", where: "M365: security.microsoft.com → Policies → Tenant Allow/Block List\nFirewall: block originating IP\nDNS/Proxy: Cisco Umbrella / Zscaler → add to block list" },
                { task: "Notify recipients", where: "Email or Teams message — template: 'A malicious email was removed from your inbox. No action needed.'" },
                { task: "Document IOCs and close ticket", where: "MISP / TheHive / ServiceNow — log all IPs, domains, hashes, URLs" },
              ],
            },
          },
          {
            label: "Yes — clicked a link",
            next: {
              id: "phish_click1", q: "Did the user enter credentials on the linked page?",
              options: [
                {
                  label: "Yes — credentials entered",
                  next: {
                    id: "phish_creds", result: true, severity: "CRITICAL",
                    type: "Credential Harvesting — Active Compromise",
                    steps: [
                      { task: "IMMEDIATELY force password reset", where: "M365: admin.microsoft.com → Users → select → Reset password\nAzure AD: portal.azure.com → Azure AD → Users → Reset password\nGoogle: admin.google.com → Users → Reset password" },
                      { task: "Revoke all active sessions and OAuth tokens", where: "Azure AD PS: Revoke-AzureADUserAllRefreshToken -ObjectId <id>\nM365 Admin: Users → select → Sign out of all sessions\nGoogle: Admin → Users → Security → Sign out of all sessions" },
                      { task: "Enable / enforce MFA immediately", where: "M365: portal.azure.com → Azure AD → Security → MFA\nGoogle: admin.google.com → Security → 2-Step Verification → Enforce\nOkta: Security → Multifactor → Enrollment policies" },
                      { task: "Review sign-in logs for unauthorized access", where: "Azure AD: portal.azure.com → Azure AD → Sign-in logs → filter by user\nM365: admin.microsoft.com → Reports → Sign-in activity\nGoogle: Admin → Reports → Login Audit" },
                      { task: "Check for new inbox rules (forward/delete)", where: "Exchange PS: Get-InboxRule -Mailbox victim@company.com\nOWA: Settings → View all → Rules\nGoogle: Admin → Users → Gmail → Filters" },
                      { task: "Sandbox the phishing URL to understand what was captured", where: "→ app.any.run (interactive browser sandbox)\n→ urlscan.io (screenshot + DOM analysis)\n→ browserling.com (live isolated browser)" },
                      { task: "Hunt for same URL click across all users", where: "M365: security.microsoft.com → Explorer → URLs tab → search URL → view all clickers\nProofpoint: TAP Dashboard → Clicks → search URL" },
                      { task: "Block all attacker infrastructure", where: "URL: M365 Tenant Allow/Block List / Cisco Umbrella\nIP: Firewall rules\nDomain: DNS sinkhole or proxy block\nEmail: Gateway sender block" },
                      { task: "Notify legal/compliance if sensitive data accessed", where: "Internal: escalate to CISO, Legal, DPO\nExternal (if GDPR breach): notify DPA within 72 hours\nExternal (if HIPAA): notify HHS OCR" },
                    ],
                  },
                },
                {
                  label: "No — link only visited",
                  next: {
                    id: "phish_linkonly", result: true, severity: "HIGH",
                    type: "Phishing Link Clicked — No Credentials",
                    steps: [
                      { task: "Full URL sandbox analysis", where: "→ app.any.run — interactive sandbox, captures full page behavior\n→ urlscan.io — screenshots, DOM, network requests\n→ hybrid-analysis.com — static + dynamic combo" },
                      { task: "Check for drive-by exploit delivery", where: "Review sandbox report for: exploit kits, JS execution, iframe redirects\nCheck EDR on user device for process spawned from browser\nCrowdStrike: Events → filter by ParentProcess=chrome.exe/msedge.exe" },
                      { task: "Scan user device with EDR", where: "CrowdStrike: Falcon → Detections → filter by hostname\nSentinelOne: Endpoints → select device → Scan\nMicrosoft Defender: security.microsoft.com → Devices → select → Run AV scan" },
                      { task: "Review DNS / proxy logs for C2 beacons", where: "Cisco Umbrella: Investigate → search hostname → DNS activity\nZscaler: Logs → Web Logs → filter by user + time\nPalo Alto: Monitor → Traffic → filter by source IP of device\nSplunk: index=dns src_ip=device_ip | stats count by query" },
                      { task: "Force credential reset as precaution", where: "M365: admin.microsoft.com → Users → select → Reset password\nAD: ADUC → right-click → Reset Password" },
                      { task: "Block all related URLs and domains", where: "M365: Tenant Allow/Block List\nCisco Umbrella: Destination Lists\nZscaler: Custom URL categories → Block" },
                    ],
                  },
                },
              ],
            },
          },
          {
            label: "Yes — opened an attachment",
            next: {
              id: "phish_attach1", q: "Did the attachment execute or request macro enabling?",
              options: [
                {
                  label: "Yes — executed / macros enabled",
                  next: {
                    id: "malware_exec", result: true, severity: "CRITICAL",
                    type: "Malware Execution via Email",
                    steps: [
                      { task: "IMMEDIATELY isolate device — do NOT power off", where: "CrowdStrike: falcon.crowdstrike.com → Hosts → select → Contain\nSentinelOne: Endpoints → select → Network Quarantine\nMicrosoft Defender: security.microsoft.com → Devices → select → Isolate" },
                      { task: "Submit attachment to malware sandbox", where: "→ app.any.run — interactive, real-time process tree\n→ hybrid-analysis.com — automated multi-engine\n→ joesandbox.com — deep analysis\nDO NOT run on production machine" },
                      { task: "Extract all IOCs from sandbox report", where: "Sandbox reports provide:\n• C2 IPs and domains\n• Dropped file hashes\n• Registry changes\n• Mutex names\n• Network signatures\nExport report as JSON/PDF from sandbox dashboard" },
                      { task: "Hunt for same hash across all endpoints", where: "CrowdStrike: Investigate → Indicator Search → SHA256 hash\nSentinelOne: Visibility → File Search → hash\nMicrosoft Defender: Advanced Hunting → DeviceFileEvents\nCarbon Black: Process Search → hash" },
                      { task: "Search DNS logs for C2 domain lookups", where: "Cisco Umbrella: Investigate → enter C2 domain → DNS History\nSplunk: index=dns query=c2domain.com\nMicrosoft Sentinel: DnsEvents | where Name == 'c2domain.com'" },
                      { task: "Check firewall logs for C2 IP connections", where: "Palo Alto: Monitor → Traffic → filter destination=C2_IP\nFortigate: Log & Report → Traffic → filter destination\nSplunk: index=firewall dest_ip=C2_IP\nMicrosoft Sentinel: AzureNetworkAnalytics_CL | where DestIP == 'C2_IP'" },
                      { task: "Check for persistence mechanisms", where: "CrowdStrike: Event Search → RegistryKey contains 'Run'\nSysinternals Autoruns: run on isolated machine\nSplunk: index=windows EventCode=13 TargetObject=*Run*\nCommon locations: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
                      { task: "Block all extracted IOCs at every layer", where: "File hash: EDR block list\nC2 IPs: Firewall deny rule\nC2 Domains: DNS sinkhole / Umbrella / Zscaler block\nEmail: Gateway sender + attachment type block" },
                      { task: "Reimage device if full compromise confirmed", where: "Pull clean OS image from your deployment server (SCCM/MDT/Jamf)\nRestore user data from backup predating infection\nVerify backup is clean before restoring (check hash/scan)" },
                    ],
                  },
                },
                {
                  label: "No — just opened / previewed",
                  next: {
                    id: "attach_open", result: true, severity: "HIGH",
                    type: "Suspicious Attachment Opened",
                    steps: [
                      { task: "Hash the attachment immediately", where: "Linux/Mac: sha256sum file.pdf\nWindows PS: Get-FileHash .\\file.pdf -Algorithm SHA256\nThen check hash at: virustotal.com/gui/home/search" },
                      { task: "Submit to sandbox for behavioral analysis", where: "→ app.any.run (interactive)\n→ hybrid-analysis.com (automated, free)\n→ joesandbox.com\nUpload from isolated machine or directly to web interface" },
                      { task: "Check EDR for suspicious child processes", where: "CrowdStrike: Detections → filter by hostname + timeframe\nSentinelOne: Threats → filter by endpoint\nMicrosoft Defender: Advanced Hunting:\nDeviceProcessEvents | where InitiatingProcessFileName in ('winword.exe','excel.exe','acrord32.exe')" },
                      { task: "If PDF: analyze structure for malicious elements", where: "Tools: pdfid.py + pdf-parser.py (didierstevens.com)\nRun on isolated machine or submit to sandbox\nRed flags: /JavaScript /OpenAction /Launch /EmbeddedFile" },
                      { task: "If Office file: check for macros", where: "Tool: oletools (pip install oletools)\nRun: olevba suspicious.docm\nRed flags: AutoOpen, AutoExec, Shell, CreateObject, WScript" },
                      { task: "Block file hash at EDR level org-wide", where: "CrowdStrike: Prevention Hashes → Add → Never Allowed\nSentinelOne: Blacklist → Add SHA256\nMicrosoft Defender: Indicators → File hashes → Block" },
                    ],
                  },
                },
              ],
            },
          },
        ],
      },
    },
    {
      label: "Business Email Compromise (BEC)",
      next: {
        id: "bec1", q: "What is the nature of the BEC?",
        options: [
          {
            label: "Financial request / wire transfer",
            next: {
              id: "bec_fin", result: true, severity: "CRITICAL",
              type: "BEC — Financial Fraud",
              steps: [
                { task: "HOLD any pending transactions IMMEDIATELY", where: "Call Finance directly by phone — do NOT use email\nContact your bank's fraud line if wire already initiated\nUS banks: call within hours for potential recall\nDocument: transaction amount, destination account, routing number" },
                { task: "Determine: spoofing vs account takeover", where: "Header analysis: does email originate from real company mail servers?\nCheck: DKIM/SPF pass + correct sending IP = possible account takeover\nCheck: DKIM/SPF fail + wrong IP = external spoofing" },
                { task: "If account takeover: review login history", where: "Azure AD: portal.azure.com → Sign-in logs → filter by compromised account\nGoogle: admin.google.com → Reports → Login Audit\nOkta: Reports → System Log → filter by user" },
                { task: "Check for inbox rules and forwarding", where: "Exchange PS: Get-InboxRule -Mailbox exec@company.com | Where {$_.ForwardTo -ne $null}\nOWA: Settings → View all → Rules\nLook for: rules forwarding to Gmail/Yahoo/external domains" },
                { task: "Check sent items for unauthorized emails", where: "Exchange PS: Get-MessageTrackingLog -Sender exec@company.com -EventId SEND\nOWA: Sent Items → sort by date → review last 7 days\nLook for: emails to finance, vendors, or banks not sent by the user" },
                { task: "Contact bank to attempt wire recall", where: "US: call your bank's wire department immediately (time-critical — hours matter)\nFile FBI IC3 report: ic3.gov (include all wire details)\nNotify cyber insurance provider\nContact recipient bank if known" },
                { task: "Preserve all evidence for legal action", where: "Export all related emails as .eml with headers\nHash all evidence files\nDocument chain of custody\nEngage legal counsel" },
              ],
            },
          },
          {
            label: "Executive impersonation (Whaling)",
            next: {
              id: "bec_exec", result: true, severity: "CRITICAL",
              type: "BEC — Executive Impersonation",
              steps: [
                { task: "Call executive directly — do NOT reply by email", where: "Use phone or personal contact\nVerify: did they actually send that request?" },
                { task: "Full header analysis to identify spoofing or compromise", where: "Paste full headers: toolbox.googleapps.com/apps/messageheader\nCheck: does email originate from company mail servers or external IP?" },
                { task: "OSINT on sender domain", where: "→ whois.domaintools.com — check domain age and registrant\n→ dnstwist.it — check if it's a lookalike domain\n→ urlscan.io — scan the domain\n→ virustotal.com — check domain reputation" },
                { task: "Review executive's account login history", where: "Azure AD: portal.azure.com → Azure AD → Sign-in logs\nGoogle: admin.google.com → Reports → Login Audit\nOkta: Reports → System Log" },
                { task: "Check for new OAuth grants on executive account", where: "Azure AD: portal.azure.com → Enterprise Applications → filter by user consent\nM365: admin.microsoft.com → Settings → Integrated apps\nGoogle: admin.google.com → Security → API Controls" },
                { task: "Alert CISO and prepare executive briefing", where: "Brief within 2 hours\nContent: what happened, risk level, what's been done, what exec needs to do\nFormat: non-technical, 1-page maximum" },
              ],
            },
          },
          {
            label: "Vendor / supplier impersonation",
            next: {
              id: "bec_vendor", result: true, severity: "HIGH",
              type: "BEC — Vendor Impersonation",
              steps: [
                { task: "Contact vendor through official website/phone number", where: "Do NOT reply to the suspicious email\nFind contact details from vendor's official website (not from the suspicious email)" },
                { task: "Check if sender domain is exact or lookalike", where: "→ dnstwist.it — enter real vendor domain, see possible typosquats\n→ Compare carefully: vendorname.com vs vendor-name.com vs vendorn4me.com\n→ whois.domaintools.com — check registration date" },
                { task: "Alert accounts payable and block any payment changes", where: "Call AP team directly by phone\nFlag any recent bank/account detail change requests from this vendor\nPlace hold on any pending payments to changed account" },
                { task: "Block attacker domain and address", where: "M365: security.microsoft.com → Tenant Allow/Block List → add domain\nEmail gateway: add to sender blocklist\nDocument for vendor notification" },
              ],
            },
          },
        ],
      },
    },
    {
      label: "Threatening / Harassing Email",
      next: {
        id: "threat1", q: "Who is the recipient?",
        options: [
          {
            label: "Regular employee",
            next: {
              id: "threat_reg", result: true, severity: "HIGH",
              type: "Threatening Email — Standard User",
              steps: [
                { task: "Preserve email — do NOT delete", where: "Export as .eml immediately\nGmail: ⋮ → Download message\nOutlook: File → Save As\nHash the file: sha256sum email.eml" },
                { task: "Full header analysis to trace origin", where: "Paste headers: toolbox.googleapps.com/apps/messageheader\nExtract originating IP\nRun IP: whois.domaintools.com + ipinfo.io + abuseipdb.com" },
                { task: "Notify HR and legal immediately", where: "Direct call or secure messaging (Teams/Slack)\nDo NOT forward threatening email to HR — share .eml securely\nEngage your organization's threat management policy" },
                { task: "File police report if credible physical threat", where: "Local law enforcement non-emergency line\nFBI Internet Crime Complaint Center: ic3.gov\nProvide: all headers, originating IP, full email content, hashed evidence" },
              ],
            },
          },
          {
            label: "VIP / Executive",
            next: {
              id: "threat_vip", result: true, severity: "CRITICAL",
              type: "Threatening Email — VIP Target",
              steps: [
                { task: "Notify security team and CISO immediately", where: "Phone call — do not use email for initial notification\nActivate VIP incident protocol\nAssign dedicated senior analyst" },
                { task: "Full forensic header trace", where: "Paste headers: toolbox.googleapps.com/apps/messageheader\nExtract IP: run through whois.domaintools.com, ipinfo.io, abuseipdb.com\nCheck: VPN/Tor/proxy at: ipqualityscore.com" },
                { task: "OSINT on sender", where: "→ Check email at: epieos.com, holehe (CLI)\n→ Search email address in: Google, LinkedIn, Facebook\n→ Check breaches: haveibeenpwned.com\n→ Check domain: whois.domaintools.com" },
                { task: "Coordinate with physical security and law enforcement", where: "Internal: physical security team\nExternal: local police non-emergency → escalate to FBI if federal threat\nIC3: ic3.gov\nProvide all digital evidence with chain of custody documentation" },
              ],
            },
          },
        ],
      },
    },
    {
      label: "Suspected Data Exfiltration",
      next: {
        id: "exfil", result: true, severity: "CRITICAL",
        type: "Data Exfiltration via Email",
        steps: [
          { task: "Identify outbound email(s) with sensitive data", where: "M365 Purview: compliance.microsoft.com → Content Search → search by sender + date\nM365 DLP: security.microsoft.com → Data Loss Prevention → Alerts\nGoogle Workspace DLP: admin.google.com → Security → DLP rules → Activity\nProofpoint DLP: dashboard → DLP Incidents" },
          { task: "Review what data was included in attachments", where: "M365 Purview: compliance.microsoft.com → Content Search → preview results\nDLP alert details show: rule triggered, sensitive data type, recipient\nOpen .eml in isolated environment to inspect content safely" },
          { task: "Identify and assess the recipient", where: "Check recipient domain:\n→ whois.domaintools.com (who owns it?)\n→ Is it personal email (gmail/yahoo)? = red flag\n→ Is it a competitor domain? = critical escalation\n→ Is it an authorized business partner?" },
          { task: "Review sender's full email history for pattern", where: "M365: compliance.microsoft.com → Content Search → search by sender\nExchange PS: Get-MessageTrackingLog -Sender insider@company.com -Start (Get-Date).AddDays(-30)\nLook for: repeated sends to same external address, large attachments, compressed files" },
          { task: "Disable sender's account if insider threat confirmed", where: "M365: admin.microsoft.com → Users → select → Block sign-in\nAzure AD: portal.azure.com → Users → select → Block sign-in toggle\nAD on-prem: ADUC → right-click → Disable Account\nDocument exact time of disable for legal timeline" },
          { task: "Engage legal and determine breach notification requirements", where: "Internal: Legal, DPO, CISO\nGDPR: notify supervisory authority within 72 hours if personal data exposed\nHIPAA: notify HHS OCR: hhs.gov/hipaa\nState laws: check applicable state breach notification laws\nCyber insurance: notify per policy terms" },
          { task: "Preserve all evidence with chain of custody", where: "Export emails: compliance.microsoft.com → Content Search → Export\nHash all exported files immediately\nDocument: who had access, what was searched, what was found\nStore in legal hold location — do not modify original mailbox" },
        ],
      },
    },
  ],
};

// ─── IOC TYPES ────────────────────────────────────────────────────────────────
const IOC_TYPES = ["IP Address", "Domain", "URL", "File Hash (SHA256)", "Email Address", "File Name", "Registry Key", "Mutex", "User Agent"];

// ─── COMPONENTS ──────────────────────────────────────────────────────────────

const inputStyle = {
  background: "#1a2235", border: "1px solid #1e2d45", borderRadius: 6,
  padding: "8px 12px", color: "#e8f0fe", fontSize: 13, outline: "none",
};

const btnStyle = (bg, color) => ({
  background: bg, color, border: `1px solid ${color}44`,
  borderRadius: 6, padding: "8px 16px", cursor: "pointer",
  fontSize: 13, fontWeight: 600, whiteSpace: "nowrap",
});

function Tag({ color, children }) {
  return (
    <span style={{
      background: color + "22", color,
      border: `1px solid ${color}44`, borderRadius: 4,
      padding: "2px 8px", fontSize: 11, fontWeight: 700,
      letterSpacing: 1, textTransform: "uppercase",
    }}>{children}</span>
  );
}

function Card({ children, style }) {
  return (
    <div style={{
      background: COLORS.surface, border: `1px solid ${COLORS.border}`,
      borderRadius: 10, padding: 20, ...style,
    }}>{children}</div>
  );
}

function SectionHeader({ children }) {
  return (
    <div style={{
      fontSize: 11, fontWeight: 700, letterSpacing: 2,
      textTransform: "uppercase", color: COLORS.accent,
      marginBottom: 14, paddingBottom: 8,
      borderBottom: `1px solid ${COLORS.border}`,
    }}>{children}</div>
  );
}

// ─── WHERE TOOLTIP ────────────────────────────────────────────────────────────

function WherePopup({ text }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ position: "relative", display: "inline-block" }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          background: open ? COLORS.accent + "33" : COLORS.accent + "18",
          color: COLORS.accent, border: `1px solid ${COLORS.accent}55`,
          borderRadius: 5, padding: "2px 9px", fontSize: 11,
          fontWeight: 700, cursor: "pointer", whiteSpace: "nowrap",
        }}
      >
        {open ? "▲ WHERE" : "▼ WHERE"}
      </button>
      {open && (
        <div style={{
          position: "absolute", zIndex: 100, left: 0, top: "calc(100% + 6px)",
          background: "#0d1526", border: `1px solid ${COLORS.accent}55`,
          borderRadius: 8, padding: "14px 16px", minWidth: 320, maxWidth: 480,
          boxShadow: "0 8px 32px #00000088",
        }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: COLORS.accent, marginBottom: 8, letterSpacing: 1 }}>WHERE TO DO THIS</div>
          <pre style={{
            fontSize: 12, color: COLORS.textPrimary, whiteSpace: "pre-wrap",
            wordBreak: "break-word", lineHeight: 1.7, margin: 0,
            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          }}>{text}</pre>
        </div>
      )}
    </div>
  );
}

function CmdBlock({ cmd }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(cmd).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); });
  };
  return (
    <div style={{
      background: "#070b14", border: `1px solid ${COLORS.border}`,
      borderRadius: 6, padding: "10px 14px", marginTop: 6,
      display: "flex", gap: 10, alignItems: "flex-start",
    }}>
      <pre style={{
        flex: 1, fontSize: 12, color: COLORS.green2,
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", lineHeight: 1.6,
      }}>{cmd}</pre>
      <button onClick={copy} style={{
        background: copied ? COLORS.success + "22" : COLORS.surfaceAlt,
        color: copied ? COLORS.success : COLORS.textMuted,
        border: `1px solid ${COLORS.border}`, borderRadius: 4,
        padding: "3px 8px", fontSize: 11, cursor: "pointer", whiteSpace: "nowrap",
      }}>{copied ? "✓" : "Copy"}</button>
    </div>
  );
}

// ─── DECISION TREE ────────────────────────────────────────────────────────────

function DecisionTree() {
  const [path, setPath] = useState([]);
  const [current, setCurrent] = useState(DECISION_TREE);

  const choose = (option) => {
    setPath([...path, { q: current.q, label: option.label }]);
    setCurrent(option.next);
  };
  const reset = () => { setPath([]); setCurrent(DECISION_TREE); };
  const back = () => {
    if (!path.length) return;
    let node = DECISION_TREE;
    const newPath = path.slice(0, -1);
    for (const step of newPath) { node = node.options.find(o => o.label === step.label).next; }
    setPath(newPath); setCurrent(node);
  };

  return (
    <div>
      {path.length > 0 && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 18, alignItems: "center" }}>
          <span style={{ color: COLORS.textMuted, fontSize: 12 }}>Start</span>
          {path.map((p, i) => (
            <span key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ color: COLORS.textMuted, fontSize: 12 }}>›</span>
              <span style={{ color: COLORS.textSecondary, fontSize: 12 }}>{p.label}</span>
            </span>
          ))}
        </div>
      )}

      {current.result ? (
        <div>
          <Card style={{ borderColor: severityColor(current.severity) + "66", marginBottom: 16 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
              <Tag color={severityColor(current.severity)}>{current.severity}</Tag>
              <span style={{ color: COLORS.textPrimary, fontWeight: 700, fontSize: 16 }}>{current.type}</span>
            </div>
            <SectionHeader>Investigation Steps — with WHERE to execute</SectionHeader>
            {current.steps.map((step, i) => (
              <div key={i} style={{
                padding: "12px 0",
                borderBottom: i < current.steps.length - 1 ? `1px solid ${COLORS.border}` : "none",
              }}>
                <div style={{ display: "flex", gap: 12, alignItems: "flex-start", marginBottom: step.where ? 8 : 0 }}>
                  <span style={{
                    minWidth: 24, height: 24, borderRadius: "50%",
                    background: COLORS.accent + "22", color: COLORS.accent,
                    fontSize: 11, fontWeight: 700,
                    display: "flex", alignItems: "center", justifyContent: "center",
                  }}>{i + 1}</span>
                  <span style={{ color: COLORS.textPrimary, fontSize: 14, lineHeight: 1.5, flex: 1 }}>{step.task}</span>
                </div>
                {step.where && (
                  <div style={{ marginLeft: 36 }}>
                    <WherePopup text={step.where} />
                  </div>
                )}
              </div>
            ))}
          </Card>
          <div style={{ display: "flex", gap: 10 }}>
            <button onClick={back} style={btnStyle(COLORS.surfaceAlt, COLORS.textSecondary)}>← Back</button>
            <button onClick={reset} style={btnStyle(COLORS.accent + "22", COLORS.accent)}>Start Over</button>
          </div>
        </div>
      ) : (
        <div>
          <Card style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 18, color: COLORS.textPrimary, fontWeight: 600, marginBottom: 4 }}>{current.q}</div>
            {!path.length && <div style={{ fontSize: 13, color: COLORS.textSecondary, marginTop: 4 }}>Answer each question to get a tailored playbook with exact platform locations</div>}
          </Card>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {current.options.map((opt, i) => (
              <button key={i} onClick={() => choose(opt)} style={{
                background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
                borderRadius: 8, padding: "14px 18px", color: COLORS.textPrimary,
                textAlign: "left", cursor: "pointer", fontSize: 14,
                display: "flex", alignItems: "center", gap: 10,
              }}
                onMouseEnter={e => e.currentTarget.style.borderColor = COLORS.accent}
                onMouseLeave={e => e.currentTarget.style.borderColor = COLORS.border}
              >
                <span style={{ color: COLORS.accent, fontSize: 12, fontWeight: 700 }}>{String.fromCharCode(65 + i)}</span>
                {opt.label}
              </button>
            ))}
          </div>
          {path.length > 0 && <button onClick={back} style={{ ...btnStyle(COLORS.surfaceAlt, COLORS.textSecondary), marginTop: 14 }}>← Back</button>}
        </div>
      )}
    </div>
  );
}

// ─── CHECKLIST ────────────────────────────────────────────────────────────────

function Checklist() {
  const [checked, setChecked] = useState({});
  const [activeSection, setActiveSection] = useState("triage");

  const toggle = (sid, idx) => {
    const key = `${sid}-${idx}`;
    setChecked(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const section = CHECKLIST_SECTIONS.find(s => s.id === activeSection);
  const done = section.items.filter((_, i) => checked[`${activeSection}-${i}`]).length;
  const pct = Math.round((done / section.items.length) * 100);

  return (
    <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
      {/* Sidebar */}
      <div style={{ minWidth: 170, flex: "0 0 170px" }}>
        {CHECKLIST_SECTIONS.map(s => {
          const sDone = s.items.filter((_, i) => checked[`${s.id}-${i}`]).length;
          return (
            <button key={s.id} onClick={() => setActiveSection(s.id)} style={{
              width: "100%",
              background: activeSection === s.id ? COLORS.accent + "18" : "transparent",
              border: `1px solid ${activeSection === s.id ? COLORS.accent : COLORS.border}`,
              borderRadius: 8, padding: "9px 12px",
              color: activeSection === s.id ? COLORS.accent : COLORS.textSecondary,
              textAlign: "left", cursor: "pointer", fontSize: 12, marginBottom: 5,
              display: "flex", justifyContent: "space-between", alignItems: "center",
            }}>
              <span>{s.icon} {s.title}</span>
              <span style={{ fontSize: 11, color: sDone === s.items.length ? COLORS.success : COLORS.textMuted }}>
                {sDone}/{s.items.length}
              </span>
            </button>
          );
        })}
        <button onClick={() => setChecked({})} style={{ ...btnStyle(COLORS.surfaceAlt, COLORS.textMuted), width: "100%", marginTop: 8, fontSize: 12 }}>Reset All</button>
      </div>

      {/* Main */}
      <div style={{ flex: 1, minWidth: 260 }}>
        <Card style={{ marginBottom: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <span style={{ color: COLORS.textPrimary, fontWeight: 700, fontSize: 15 }}>{section.icon} {section.title}</span>
            <span style={{ color: pct === 100 ? COLORS.success : COLORS.accent, fontWeight: 700 }}>{pct}%</span>
          </div>
          <div style={{ height: 4, background: COLORS.border, borderRadius: 2, overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${pct}%`, background: pct === 100 ? COLORS.success : COLORS.accent, borderRadius: 2, transition: "width 0.3s" }} />
          </div>
        </Card>

        {section.items.map((item, i) => {
          const key = `${activeSection}-${i}`;
          const isChecked = !!checked[key];
          return (
            <div key={i} style={{
              padding: "12px 14px",
              background: isChecked ? COLORS.success + "0a" : COLORS.surfaceAlt,
              border: `1px solid ${isChecked ? COLORS.success + "44" : COLORS.border}`,
              borderRadius: 8, marginBottom: 8,
            }}>
              <div style={{ display: "flex", gap: 12, alignItems: "flex-start", cursor: "pointer" }} onClick={() => toggle(activeSection, i)}>
                <div style={{
                  minWidth: 20, height: 20, borderRadius: 4,
                  border: `2px solid ${isChecked ? COLORS.success : COLORS.textMuted}`,
                  background: isChecked ? COLORS.success : "transparent",
                  display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
                }}>
                  {isChecked && <span style={{ color: "#000", fontSize: 11, fontWeight: 900 }}>✓</span>}
                </div>
                <span style={{
                  fontSize: 13, color: isChecked ? COLORS.textMuted : COLORS.textPrimary,
                  textDecoration: isChecked ? "line-through" : "none", lineHeight: 1.5, flex: 1,
                }}>{item.task}</span>
              </div>
              {(item.where || item.cmd) && (
                <div style={{ marginLeft: 32, marginTop: 8, display: "flex", flexDirection: "column", gap: 6 }}>
                  {item.where && <WherePopup text={item.where} />}
                  {item.cmd && <CmdBlock cmd={item.cmd} />}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── IOC TRACKER ─────────────────────────────────────────────────────────────

function IOCTracker() {
  const [iocs, setIocs] = useState([]);
  const [form, setForm] = useState({ type: IOC_TYPES[0], value: "", severity: "HIGH", notes: "" });

  const add = () => {
    if (!form.value.trim()) return;
    setIocs([...iocs, { ...form, id: Date.now(), blocked: false }]);
    setForm({ type: form.type, value: "", severity: "HIGH", notes: "" });
  };
  const toggleBlocked = id => setIocs(iocs.map(i => i.id === id ? { ...i, blocked: !i.blocked } : i));
  const remove = id => setIocs(iocs.filter(i => i.id !== id));

  const exportCSV = () => {
    const rows = [["Type", "Value", "Severity", "Blocked", "Notes"],
      ...iocs.map(i => [i.type, i.value, i.severity, i.blocked ? "Yes" : "No", i.notes])];
    const csv = rows.map(r => r.map(c => `"${c}"`).join(",")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = "iocs_export.csv"; a.click();
  };

  const BLOCK_WHERE = {
    "IP Address": "Firewall: add deny rule\nM365: Anti-spam → Connection filter → IP Block list\nProofpoint: Spam Detection → IP Reputation\nCisco Umbrella: Policies → Destination Lists",
    "Domain": "DNS: add NXDOMAIN response\nCisco Umbrella: Policies → Destination Lists\nZscaler: URL Filtering → Custom Categories → Block\nM365: Tenant Allow/Block List → Domains",
    "URL": "M365: Tenant Allow/Block List → URLs\nPalo Alto: URL Filtering profile → Block list\nZscaler: URL & Cloud App Control\nProofpoint: URL Defense → block list",
    "File Hash (SHA256)": "CrowdStrike: Prevention Hashes → Add → Never Allowed\nSentinelOne: Blacklist → Add SHA256\nMicrosoft Defender: Indicators → File hashes → Block\nCarbon Black: Enforce → Banned Hashes",
    "Email Address": "M365: Tenant Allow/Block List → Senders\nExchange: New-TransportRule → reject from sender\nProofpoint: Email Firewall → Blocklist\nMimecast: Blocked Senders",
  };

  return (
    <div>
      <Card style={{ marginBottom: 16 }}>
        <SectionHeader>Add Indicator of Compromise</SectionHeader>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <select value={form.type} onChange={e => setForm({ ...form, type: e.target.value })} style={inputStyle}>
            {IOC_TYPES.map(t => <option key={t}>{t}</option>)}
          </select>
          <input placeholder="Value (IP, domain, hash, URL...)" value={form.value}
            onChange={e => setForm({ ...form, value: e.target.value })}
            onKeyDown={e => e.key === "Enter" && add()}
            style={{ ...inputStyle, flex: 2, minWidth: 180 }} />
          <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })} style={inputStyle}>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => <option key={s}>{s}</option>)}
          </select>
          <input placeholder="Notes (optional)" value={form.notes}
            onChange={e => setForm({ ...form, notes: e.target.value })}
            style={{ ...inputStyle, flex: 2, minWidth: 120 }} />
          <button onClick={add} style={btnStyle(COLORS.accent, COLORS.bg)}>+ Add</button>
        </div>
      </Card>

      {iocs.length === 0 ? (
        <div style={{ textAlign: "center", color: COLORS.textMuted, padding: 40, fontSize: 14 }}>
          No IOCs logged yet. Add indicators above.
        </div>
      ) : (
        <>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <span style={{ color: COLORS.textSecondary, fontSize: 13 }}>{iocs.length} indicator{iocs.length !== 1 ? "s" : ""} — {iocs.filter(i => i.blocked).length} blocked</span>
            <button onClick={exportCSV} style={btnStyle(COLORS.surfaceAlt, COLORS.accent)}>Export CSV</button>
          </div>
          {iocs.map(ioc => (
            <div key={ioc.id} style={{
              padding: "10px 14px", marginBottom: 8,
              background: ioc.blocked ? COLORS.success + "0a" : COLORS.surfaceAlt,
              border: `1px solid ${ioc.blocked ? COLORS.success + "44" : COLORS.border}`,
              borderRadius: 8,
            }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                <Tag color={severityColor(ioc.severity)}>{ioc.severity}</Tag>
                <Tag color={COLORS.accentDim}>{ioc.type}</Tag>
                <span style={{
                  flex: 1, fontFamily: "monospace", fontSize: 13,
                  color: ioc.blocked ? COLORS.textMuted : COLORS.textPrimary,
                  textDecoration: ioc.blocked ? "line-through" : "none", wordBreak: "break-all",
                }}>{ioc.value}</span>
                {ioc.notes && <span style={{ fontSize: 12, color: COLORS.textMuted }}>{ioc.notes}</span>}
                <button onClick={() => toggleBlocked(ioc.id)} style={btnStyle(
                  ioc.blocked ? COLORS.success + "22" : COLORS.surfaceAlt,
                  ioc.blocked ? COLORS.success : COLORS.textSecondary,
                )}>{ioc.blocked ? "✓ Blocked" : "Mark Blocked"}</button>
                <button onClick={() => remove(ioc.id)} style={{ ...btnStyle(COLORS.danger + "18", COLORS.danger), padding: "4px 10px" }}>✕</button>
              </div>
              {BLOCK_WHERE[ioc.type] && !ioc.blocked && (
                <div style={{ marginTop: 8 }}>
                  <WherePopup text={`HOW TO BLOCK — ${ioc.type}:\n${BLOCK_WHERE[ioc.type]}`} />
                </div>
              )}
            </div>
          ))}
        </>
      )}
    </div>
  );
}

// ─── USER PROTOCOL ────────────────────────────────────────────────────────────

function UserProtocol() {
  const [mode, setMode] = useState(null);

  const normalSteps = [
    {
      phase: "Triage", color: COLORS.accent,
      items: [
        { task: "Log report in ticketing system", where: "ServiceNow: create incident ticket\nJira: create bug/incident issue\nTheHive: new case → fill template" },
        { task: "Retrieve email from quarantine", where: "M365: security.microsoft.com → Email & Collaboration → Review → Quarantine\nProofpoint: Administration → Message Center\nMimecast: Gateway → Held Messages" },
        { task: "Check if others received same email", where: "M365 Explorer: security.microsoft.com → Explorer → search by Subject/Sender\nExchange PS: Get-MessageTrackingLog -Sender attacker@evil.com" },
        { task: "Assign severity: Low / Medium", where: "No interaction = MEDIUM (4-8hr SLA)\nEmail auto-blocked = LOW (24hr SLA)\nDocument in ticket" },
      ],
    },
    {
      phase: "Analyze", color: COLORS.warn,
      items: [
        { task: "Header analysis", where: "Paste into: toolbox.googleapps.com/apps/messageheader\nCheck SPF/DKIM/DMARC in Authentication-Results header" },
        { task: "URL reputation check", where: "→ virustotal.com/gui/home/url\n→ urlscan.io\n→ phishtank.org/check.php" },
        { task: "Attachment hash check", where: "sha256sum file.ext (Linux) | Get-FileHash (Win)\nCheck at: virustotal.com/gui/home/search" },
        { task: "Compare against known campaigns", where: "→ virustotal.com → check if same indicators are flagged\n→ Your SIEM: search for same sender/subject historically\n→ Abuse.ch: bazaar.abuse.ch, urlhaus.abuse.ch" },
      ],
    },
    {
      phase: "Contain", color: COLORS.high,
      items: [
        { task: "Quarantine email org-wide", where: "M365 PowerShell: New-ComplianceSearch + New-ComplianceSearchAction -Purge\nM365 UI: Explorer → select → Remediate → Soft Delete\nProofpoint: Message Center → Quarantine selected" },
        { task: "Block sender / domain / IP", where: "M365: security.microsoft.com → Policies → Tenant Allow/Block List\nFirewall: add originating IP to deny list\nGateway: add sender to blocklist" },
        { task: "Block URLs and file hashes", where: "URLs: M365 Tenant Allow/Block List / Cisco Umbrella / Zscaler\nHashes: CrowdStrike Prevention Hashes / Defender Indicators" },
      ],
    },
    {
      phase: "Notify", color: COLORS.success,
      items: [
        { task: "Inform affected users", where: "Send via Teams/Slack or phone (if email is compromised)\nTemplate: 'A malicious email was removed from your inbox. No further action needed.'" },
        { task: "Escalate if interaction occurred", where: "Immediately escalate to HIGH/CRITICAL if:\n• User clicked a link → credential risk\n• User opened attachment → malware risk\nActivate relevant playbook" },
      ],
    },
    {
      phase: "Close", color: COLORS.textSecondary,
      items: [
        { task: "Document findings and IOCs", where: "MISP / TheHive / ServiceNow\nLog: all IPs, domains, hashes, sender details, timestamps" },
        { task: "Tune email filters", where: "M365: Anti-spam / Anti-phishing policies → update rules\nProofpoint: Email Firewall → add new pattern rule\nMimecast: Gateway → Policies → update" },
      ],
    },
  ];

  const vipSteps = [
    {
      phase: "Immediate Alert (0–15 min)", color: COLORS.critical,
      items: [
        { task: "Alert IR Lead immediately", where: "Phone call — do NOT use email for initial notification\nActivate on-call rotation if outside business hours" },
        { task: "Alert CISO within 30 minutes", where: "Direct call or secure messaging\nBrief: who is targeted, what type of attack, current status" },
        { task: "Open CRITICAL incident ticket", where: "ServiceNow / Jira / TheHive\nPriority: Critical / P1\nTag: VIP, Executive, requires-escalation" },
        { task: "Assign dedicated senior analyst", where: "This analyst owns the case end-to-end\nNo task switching — full focus on this incident" },
      ],
    },
    {
      phase: "Direct VIP Contact (0–30 min)", color: COLORS.high,
      items: [
        { task: "Call VIP or EA — NOT via email", where: "Use: office phone, mobile, EA contact\nNever email: attacker may be monitoring the inbox\nAsk: Did you open/click/reply/provide any information?" },
        { task: "Instruct VIP: do not interact further", where: "Script: 'Do not reply to the email, do not click anything, do not forward it. We are handling it.'" },
        { task: "Assess device risk", where: "If VIP interacted: is device at risk?\nDevice isolation decision made jointly with IR lead" },
      ],
    },
    {
      phase: "Deep Investigation", color: COLORS.warn,
      items: [
        { task: "Full manual header analysis", where: "Paste into: toolbox.googleapps.com/apps/messageheader\nDo not rely on automated tools only for VIP cases — manual review required" },
        { task: "OSINT on sender identity", where: "→ whois.domaintools.com (domain registration)\n→ dnstwist.it (lookalike domain check)\n→ epieos.com (email OSINT)\n→ holehe CLI (registered accounts)\n→ LinkedIn / Google search on sender" },
        { task: "Review VIP account login history", where: "Azure AD: portal.azure.com → Sign-in logs → filter by VIP account\nGoogle: admin.google.com → Reports → Login Audit\nOkta: Reports → System Log → filter by VIP user\nLook for: new countries, unknown devices, odd hours" },
        { task: "Check OAuth apps, forwarding rules, delegates", where: "OAuth: portal.azure.com → Enterprise Applications → filter by user\nInbox rules: Get-InboxRule -Mailbox vip@company.com\nDelegates: Get-MailboxPermission -Identity vip@company.com" },
        { task: "Check sent items for unauthorized emails", where: "OWA: Sent Items → sort by date → review\nExchange PS: Get-MessageTrackingLog -Sender vip@company.com -EventId SEND\nLook for: unusual recipients, financial requests, password resets" },
        { task: "Check threat intel for VIP targeting", where: "→ Have I Been Pwned: haveibeenpwned.com (email exposure)\n→ Dark web monitoring: your threat intel platform / Recorded Future\n→ OSINT: search VIP name + 'phishing' or 'targeted'\n→ FS-ISAC / sector ISAC for campaign intel" },
      ],
    },
    {
      phase: "Scope & Contain", color: COLORS.accent,
      items: [
        { task: "Determine: account compromised or external spoofing?", where: "Compromised = email passes SPF/DKIM + originates from company server\nSpoofed = fails SPF/DKIM + originates from external IP\nConfirm with full header analysis" },
        { task: "Isolate device if interaction occurred", where: "CrowdStrike: Hosts → select VIP device → Contain\nSentinelOne: Endpoints → select → Network Quarantine\nMicrosoft Defender: Devices → select → Isolate device" },
        { task: "Revoke sessions + enforce MFA", where: "Azure AD PS: Revoke-AzureADUserAllRefreshToken -ObjectId <id>\nM365 Admin: Users → select → Sign out of all sessions\nMFA: portal.azure.com → Azure AD → Security → MFA → require re-registration" },
        { task: "Search for same campaign targeting other VIPs", where: "M365 Explorer: search same sender/subject → filter by VIP recipient list\nProofpoint TAP: Targeted Attack Protection → Campaign view\nCheck all C-suite, finance leads, IT admins" },
      ],
    },
    {
      phase: "Executive Briefing (within 2 hours)", color: COLORS.success,
      items: [
        { task: "Prepare non-technical briefing", where: "Format: 1-page max, plain language\nContent: What happened, who was targeted, current risk level, what security did, what VIP needs to do next\nDeliver: in-person or secure video call" },
        { task: "Brief CISO and legal", where: "CISO: full technical details + risk assessment\nLegal: potential data exposure, regulatory requirements, evidence preservation\nCyber insurance: notify if breach threshold met" },
      ],
    },
    {
      phase: "Enhanced Monitoring (30 days)", color: COLORS.textSecondary,
      items: [
        { task: "Enable enhanced logging on VIP accounts", where: "Azure AD: enable sign-in risk policies for VIP group\nM365 Defender: set up custom alert for VIP account anomalies\nSIEM: create high-priority alert rule for VIP identity events" },
        { task: "Set alerts for login anomalies", where: "Azure AD Conditional Access: flag impossible travel, new countries, new devices\nMicrosoft Sentinel: create analytic rule for VIP sign-in from new location\nOkta: Behavior Detection → enable for VIP group" },
        { task: "Weekly review of VIP email rules", where: "PowerShell: Get-InboxRule -Mailbox vip@company.com (run weekly)\nCheck for: new auto-forward rules, new delegates, new connected apps\nDocument each review in the incident ticket" },
      ],
    },
  ];

  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 20 }}>
        <button onClick={() => setMode("normal")} style={{
          flex: 1, padding: "16px", borderRadius: 10,
          background: mode === "normal" ? COLORS.accent + "22" : COLORS.surfaceAlt,
          border: `2px solid ${mode === "normal" ? COLORS.accent : COLORS.border}`,
          color: mode === "normal" ? COLORS.accent : COLORS.textSecondary,
          cursor: "pointer", fontSize: 15, fontWeight: 600,
        }}>👤 Normal User</button>
        <button onClick={() => setMode("vip")} style={{
          flex: 1, padding: "16px", borderRadius: 10,
          background: mode === "vip" ? COLORS.critical + "22" : COLORS.surfaceAlt,
          border: `2px solid ${mode === "vip" ? COLORS.critical : COLORS.border}`,
          color: mode === "vip" ? COLORS.critical : COLORS.textSecondary,
          cursor: "pointer", fontSize: 15, fontWeight: 600,
        }}>👑 VIP / Executive</button>
      </div>

      {mode === null && (
        <div style={{ textAlign: "center", color: COLORS.textMuted, padding: 40, fontSize: 14 }}>
          Select a user type to view the investigation protocol with exact locations
        </div>
      )}

      {(mode === "normal" ? normalSteps : mode === "vip" ? vipSteps : []).map((s, i) => {
        const steps = mode === "normal" ? normalSteps : vipSteps;
        return (
          <div key={i} style={{ display: "flex", gap: 14, marginBottom: 12 }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
              <div style={{
                width: 32, height: 32, borderRadius: "50%",
                background: s.color + "22", border: `2px solid ${s.color}`,
                display: "flex", alignItems: "center", justifyContent: "center",
                color: s.color, fontWeight: 700, fontSize: 13, flexShrink: 0,
              }}>{i + 1}</div>
              {i < steps.length - 1 && <div style={{ width: 2, flex: 1, background: COLORS.border, margin: "4px 0" }} />}
            </div>
            <Card style={{ flex: 1, marginBottom: 0 }}>
              <div style={{ color: s.color, fontWeight: 700, fontSize: 13, marginBottom: 10 }}>{s.phase}</div>
              {s.items.map((item, j) => (
                <div key={j} style={{
                  padding: "8px 0",
                  borderBottom: j < s.items.length - 1 ? `1px solid ${COLORS.border}` : "none",
                }}>
                  <div style={{ fontSize: 13, color: COLORS.textPrimary, marginBottom: item.where ? 6 : 0 }}>{item.task}</div>
                  {item.where && <WherePopup text={item.where} />}
                </div>
              ))}
            </Card>
          </div>
        );
      })}
    </div>
  );
}

// ─── APP ──────────────────────────────────────────────────────────────────────

const TABS = [
  { id: "tree", label: "🌲 Decision Tree" },
  { id: "checklist", label: "✅ Checklist" },
  { id: "ioc", label: "🎯 IOC Tracker" },
  { id: "protocol", label: "👤 User Protocol" },
];

export default function App() {
  const [tab, setTab] = useState("tree");
  return (
    <div style={{
      background: COLORS.bg, minHeight: "100vh",
      fontFamily: "'Inter', 'Segoe UI', system-ui, sans-serif",
      color: COLORS.textPrimary, padding: "0 0 40px",
    }}>
      <div style={{
        background: COLORS.surface, borderBottom: `1px solid ${COLORS.border}`,
        padding: "18px 24px", display: "flex", alignItems: "center", gap: 14, marginBottom: 24,
      }}>
        <div style={{
          width: 36, height: 36, borderRadius: 8,
          background: COLORS.accent + "22", border: `1px solid ${COLORS.accent}44`,
          display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18,
        }}>📧</div>
        <div>
          <div style={{ fontWeight: 800, fontSize: 16, letterSpacing: 0.5 }}>Email Investigation Toolkit v2</div>
          <div style={{ fontSize: 12, color: COLORS.textMuted, marginTop: 1 }}>Every step includes WHERE to go — platform paths, URLs, commands</div>
        </div>
      </div>

      <div style={{ maxWidth: 900, margin: "0 auto", padding: "0 16px" }}>
        <div style={{ display: "flex", gap: 6, marginBottom: 20, flexWrap: "wrap" }}>
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              background: tab === t.id ? COLORS.accent : COLORS.surfaceAlt,
              color: tab === t.id ? COLORS.bg : COLORS.textSecondary,
              border: `1px solid ${tab === t.id ? COLORS.accent : COLORS.border}`,
              borderRadius: 8, padding: "9px 16px", cursor: "pointer",
              fontSize: 13, fontWeight: tab === t.id ? 700 : 500,
            }}>{t.label}</button>
          ))}
        </div>

        {tab === "tree" && <DecisionTree />}
        {tab === "checklist" && <Checklist />}
        {tab === "ioc" && <IOCTracker />}
        {tab === "protocol" && <UserProtocol />}
      </div>
    </div>
  );
}
