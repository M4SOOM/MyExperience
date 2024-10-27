# Cyber Managed Services Inc. (CyberMSI)

<img src="https://i.postimg.cc/wB10vRgb/cybermsi-logo.jpg" align="right" alt="CyberMSI" width="150" height="150">

**About Company :**<br>
Our company leads in next-generation AI-driven cybersecurity, leveraging Microsoft Defender XDR, Microsoft<br> Sentinel, and Microsoft Copilot for Security alongside expert insights. We provide around-the-clock managed services in Extended Detection and Response (XDR), Identity Threat Detection & Response (ITDR), Data Security, and Security Exposure Management.
Trusted by numerous mid-sized organizations in over 30 countries across four continents, we excel in safeguarding against business disruptions and data loss. Our comprehensive protection spans identities, endpoints, data, apps, infrastructure, IoT, and network, enforcing zero trust security throughout the organization.<br> With a 21-minute Mean Time to Respond (MTTR), we don’t just respond to threats; we fully mitigate them.
<br>As a Microsoft security partner, we specialize in Microsoft Copilot, Microsoft Defender XDR, Microsoft Sentinel,<br> Microsoft Purview, Microsoft Defender for Cloud , Microsoft Defender for Endpoints, Microsoft Defender for Office,<br> Microsoft Cloud App Security, Microsoft Defender for Identity, Microsoft Entra ID, and Microsoft Security Exposure Management.

 <h2 align="center"></h2>

  <p align="center">
</p>

### Role Description - Cybersecurity Analyst

As part of the Security Operations Center (SOC) team, analysts will manage the full Incident Management (IM) lifecycle. They will detect, analyze, and triage security incidents using monitoring tools, categorizing them by severity and assessing their potential impact. Analysts will conduct detailed investigations, leveraging Microsoft cybersecurity tools to gather evidence and perform root cause analyses to identify vulnerabilities. In addition, they will implement response strategies, including system isolation, patching, and malware removal, collaborating with IT and network teams to ensure swift resolution. Effective customer communication is key, as analysts will provide timely updates and draft concise incident reports. Analysts will also maintain accurate documentation in Jira, ensuring all incidents are tracked through their lifecycle, and participate in post-incident reviews to refine processes. They will handle escalations, coordinate with stakeholders, and contribute to post-incident evaluations, recommending long-term remediation actions to enhance the organization’s security posture. This role enables analysts to develop key skills in managing cybersecurity incidents and addressing real-world security challenges.

### Duration : Sept 2024 - Present
 <h2 align="center"></h2>

  <p align="center">
</p>

### Tools Used :
![My Skills](https://go-skill-icons.vercel.app/api/icons?i=azure,jira&theme=light)<img src="https://github.com/MasoomEXE/Test1/blob/main/Azure-Sentinel.svg" alt="Dashboard Icon" width="51" height="51"><img src="https://github.com/M4SOOM/MyExperience/blob/main/Icons/XDR-icon.svg">
<h2 align="center"></h2><p align="center"></p>


## Table of contents
- [Incident Identification and Categorization](#incident-identification-and-categorization)
- [Incident Investigation and Root Cause Analysis](#incident-investigation-and-root-cause-analysis)
- [How to use them](#how-to-use-them)
- [Roadmap](#roadmap)
- [Releases](#releases)
- [Contributors](#contributors)
- [Licence](#licence)

<hr>

### Incident Identification and Categorization
1. Detect, analyze, and triage security incidents using monitoring tools and alerts from various systems and platforms:<br>
As part of the Incident Management lifecycle, your role involves actively monitoring security tools and systems to detect potential threats and anomalous behavior. Using specialized platforms such as SIEM (Security Information and Event Management) systems, you will analyze alerts triggered by abnormal activities across network traffic, endpoints, user behavior, and applications. This process includes evaluating each alert to determine its validity, relevance, and potential impact, and then triaging it—sorting incidents based on severity levels (e.g., Critical, High, Medium, low) to prioritize response efforts. This analysis is essential in filtering out false positives, identifying genuine threats, and ensuring the most serious incidents are addressed swiftly to protect the organization’s assets and data integrity.

<img src="Images/MSI/2.jpg">

I used "Azure Lighthouse" to gain a unified view of incidents across multiple workspaces in Azure Sentinel. By selecting all relevant workspaces within Sentinel, I accessed a consolidated overview, which enabled me to monitor and investigate security incidents occurring across different environments without switching between separate dashboards. Azure Lighthouse provided a centralized view, aggregating alerts from all connected workspaces, allowing you to quickly spot patterns, prioritize incidents, and maintain situational awareness over the security posture of multiple client or organizational environments.

This method ensured timely detection and response to incidents by providing me with quick access to key metrics and real-time data across all workspaces, which also allowed me to jump directly into any high-severity incidents, initiate triage, and begin investigations without delay.

2. Analyzing the incidents:<br>
I reviewed incidents in Azure Sentinel and assessed their severity by analyzing involved entities, such as IP addresses, user accounts, devices, or applications, which could indicate a potential risk. When a new incident appeared, i began by examining the specific entities flagged as malicious or suspicious. By reviewing details such as whether an entity was associated with known threats, patterns of abnormal behavior, or prior alerts, you assessed its potential to harm user devices or the broader network.<br>
Here's an example of me doing it.

<img src="Images/MSI/6.jpg">

If an entity presented a significant threat (like a compromised administrator account or a critical infrastructure device) it could lead to high impact on security, data, or operational continuity. Although Sentinel automatically assigns a severity level to incidents, sometimes investigations reveal high-value entities that may not have been fully reflected in the initial classification, By following the organizational guidelines, i ensured that all incidents (during my shift) were accurately prioritized (High, Medium, Low, Informational), directing resources toward the most critical threats while maintaining a proactive approach to emerging risks.

### Incident Investigation and Root Cause Analysis
1. Incident Investigation: <br>
We start by reviewing each entity to see if it has a history of suspicious activity or has been involved in previous incidents. Sentinel enables pivoting on these entities across multiple data sources, allowing analysts to evaluate their connections to other events or alerts. After reviewing entities in Sentinel, the analyst can seamlessly transition to Microsoft Defender XDR, where they’ll find detailed insights on each endpoint, network, and email activity associated with the alert. Microsoft Defender XDR consolidates endpoint, identity, and email threat intelligence, providing a unified view of the incident. Here, analysts can delve into activities directly related to compromised endpoints, lateral movement, and attacker persistence strategies.

<img src="Images/MSI/5.jpg">

The "Attack Story" section in Microsoft Defender XDR is pivotal for understanding the “who, what, and how” of an incident. It provides a visual representation of the entire attack sequence, detailing the alert’s origin, progression, and any related tactics or techniques. By examining the attack story, analysts can see how the incident unfolded over time, identify attacker behavior patterns, and understand which assets or data may have been affected. Each step in the attack story can be clicked on for additional details, which often include logs, commands executed, and impacted resources.
- Search File Hashes on Threat Intelligence Platforms<br>
  File Hash Analysis: Any suspicious files or executables detected during the investigation are converted into hashes (MD5, SHA-1, or SHA-256) and checked against reputable threat intelligence databases like VirusTotal.
- Check Email Entities for Spam or Phishing URLs<br>
  Email Entity Analysis: If the incident involves email-based threats, analysts focus on email entities like sender addresses, URLs, and attachments to assess potential phishing or spam content. URLs embedded in the email are inspected for redirections to known phishing sites or domains associated with malicious campaigns. Threat intelligence tools may also help identify IP addresses or domains that frequently host phishing content.<br>

2. Root Cause Analysis: <br>
Then we start by investigating device timeline within a specific timeframe to focus on, typically within a window of ±30 minutes from the first detection of malicious activity or suspicious alert. This allows the analyst to examine the immediate lead-up to and aftermath of the suspected compromise without being overwhelmed by unrelated data. Firstly start with examining key events on system and security logs to identify significant events, such as logins, logoffs, and attempts to escalate privileges, which could indicate attacker activity. Windows Event Logs, for example, can reveal details about user sessions, security policy changes, or suspicious file modifications.

<img src="Images/MSI/Device_Timeline.jpg">

- Unusual Executables: I reviewed processes and executables that were initiated on the device within the scoped timeline. They identify files that may not align with typical software behavior or scheduled tasks and determine if they match known malicious file hashes using threat intelligence platforms like VirusTotal. Suspicious executables are further analyzed to see if they attempted to establish persistence on the system (e.g., by adding registry keys or configuring scheduled tasks). If persistence mechanisms are identified, it can be a significant clue in understanding the attack's goals.
- Outbound Connections: During the specified timeframe, we look for unusual network traffic, particularly outbound connections that may indicate data exfiltration attempts or communication with command-and-control (C2) servers.
