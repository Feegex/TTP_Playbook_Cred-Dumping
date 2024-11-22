# TTP_Playbook_Cred-Dumping
Objective: Detect and mitigate credential dumping to prevent unauthorized access.
Trigger: Alert from endpoint detection and response (EDR) tool on suspicious memory access or tools like Mimikatz.
Steps:
Detection and Triage

MITRE ATT&CK Mapping:
Tactic: Credential Access
Technique: T1003 (Credential Dumping)
Details: Review EDR or SIEM alerts to confirm the use of credential dumping tools or methods.
Tools: EDR (e.g., CrowdStrike, SentinelOne), SIEM (e.g., Splunk, ELK Stack).
Containment

MITRE ATT&CK Mapping:
Tactic: Containment
Technique: Quarantine Endpoint
Details: Isolate the affected endpoint from the network.
Tools: Network Access Control (e.g., Cisco ISE), EDR.
Investigation

MITRE ATT&CK Mapping:
Tactic: Discovery
Technique: T1083 (File and Directory Discovery), T1087 (Account Discovery)
Details:
Examine logs for lateral movement.
Identify accounts potentially affected.
Tools: Log analysis (e.g., Splunk), memory forensics tools (e.g., Volatility).
Eradication

MITRE ATT&CK Mapping:
Tactic: Privilege Escalation
Technique: T1078 (Valid Accounts)
Details:
Reset compromised credentials.
Patch vulnerabilities that enabled the dumping.
Tools: Active Directory management tools.
Recovery

MITRE ATT&CK Mapping:
Tactic: Impact
Technique: Restore Impacted Services
Details:
Reinstate endpoints and systems in production.
Monitor for recurring activity.
Tools: Monitoring solutions (e.g., Nagios).
Post-Incident Activities

MITRE ATT&CK Mapping:
Tactic: Defense Evasion
Technique: Detect and analyze persistence mechanisms.
Details:
Conduct a post-incident review to improve defenses.
Update threat detection rules.
Tools: Threat intelligence platforms.
