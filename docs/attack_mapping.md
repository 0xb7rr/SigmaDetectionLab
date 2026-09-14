# MITRE ATT&CK Coverage Map

Each rule in this repo maps to at least one ATT&CK technique. This table is
the kind of coverage summary a detection engineering team keeps to track
which parts of the ATT&CK matrix they can actually see, and which parts are
still blind spots.

| Rule | Tactic | Technique | Data Source | Severity |
|---|---|---|---|---|
| `kerberoasting.yml` | Credential Access | [T1558.003 - Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) | Windows Security Event 4769 | Medium |
| `powershell_obfuscation.yml` | Execution / Defense Evasion | [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/), [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) | Sysmon Event ID 1 / Windows 4688 | High |
| `lolbin_certutil_abuse.yml` | Command and Control / Defense Evasion | [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/), [T1218.011 - Signed Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/) | Sysmon Event ID 1 / Windows 4688 | High |
| `lsass_credential_dumping.yml` | Credential Access | [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) | Sysmon Event ID 10 (ProcessAccess) | Critical |
| `dns_tunneling.yml` | Command and Control / Exfiltration | [T1071.004 - Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/) | DNS resolver / firewall / Zeek `dns.log` | Medium |

## Why these five

These were chosen to span the attack lifecycle rather than cluster on one
tactic:

1. **Kerberoasting** - a post-compromise privilege escalation / lateral
   movement enabler that's entirely detectable from default AD logging.
2. **PowerShell obfuscation** - the most common execution vector in
   real-world intrusions (phishing → macro → PowerShell).
3. **LOLBin abuse (certutil)** - shows understanding of "living off the
   land" techniques that evade binary-allowlisting and naive AV.
4. **LSASS dumping** - the single most valuable credential-theft technique
   to catch, since it directly enables domain-wide lateral movement.
5. **DNS tunneling** - covers the exfiltration/C2 side of the kill chain,
   which is often the last line of defense once a host is compromised.

## Known Gaps (intentionally out of scope for v1)

- Initial access (phishing delivery, exploit-based entry) - not covered;
  best handled by email security and EDR, not log-based Sigma rules.
- Lateral movement via SMB/WMI/PsExec - a natural "v2" addition once this
  rule set is validated further.
- Cloud-native techniques (Azure AD, AWS IAM abuse) - this pack is
  currently Windows/on-prem focused.

## How to Extend This Table

When adding a new rule:
1. Add a row here with the rule filename, tactic, technique ID, data
   source, and severity.
2. Add the corresponding `attack.tXXXX` tag to the rule's YAML.
3. Add a sample log file with at least one true-positive and one
   true-negative (and, where relevant, a documented false positive like
   the SPF/TXT case in `dns_tunneling.yml`).
