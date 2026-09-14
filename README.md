# Sigma Detection Lab

A small, self-contained detection engineering lab: five Sigma rules covering
distinct MITRE ATT&CK techniques, paired with realistic sample logs (both
malicious and benign) and a validator script that proves each rule fires
exactly when it should.

Built to demonstrate blue-team / detection-engineering fundamentals: reading
attacker behavior, translating it into structured detection logic, and
testing that logic empirically rather than just writing rules and hoping.

## Why This Exists

Most student security portfolios are entirely offensive: CTF writeups,
exploit PoCs, pentest reports. This repo is the other half of the job -
proving you can also **detect** the techniques you know how to execute,
and that you understand the operational reality of detection engineering
(false positives, log source requirements, ATT&CK mapping) rather than
just writing regex against a single sample.

## Repo Structure

```
sigma-detection-lab/
├── rules/                          # 5 Sigma detection rules (YAML)
│   ├── kerberoasting.yml
│   ├── powershell_obfuscation.yml
│   ├── lolbin_certutil_abuse.yml
│   ├── lsass_credential_dumping.yml
│   └── dns_tunneling.yml
├── sample_logs/                    # Realistic logs, each entry labeled
│   └── *_sample.json               #   with an expected_detection outcome
├── validator/
│   └── validate_rules.py           # Runs every rule against its sample log
├── docs/
│   └── attack_mapping.md           # ATT&CK technique coverage table
├── requirements.txt
└── README.md
```

## Detection Coverage

| Rule | ATT&CK Technique | Severity |
|---|---|---|
| Kerberoasting (RC4 TGS requests) | T1558.003 | Medium |
| PowerShell obfuscation | T1059.001 / T1027 | High |
| certutil LOLBin abuse | T1105 / T1218.011 | High |
| LSASS credential dumping | T1003.001 | Critical |
| DNS tunneling | T1071.004 | Medium |

Full writeup of *why* these five and what's intentionally out of scope for
v1 is in [`docs/attack_mapping.md`](docs/attack_mapping.md).

## Running the Validator

```bash
pip install -r requirements.txt
python3 validator/validate_rules.py
```

Expected output: every log entry is scored `PASS` against its labeled
`expected_detection` value, e.g.

```
Rule: Potential Kerberoasting Activity via RC4 TGS Requests
------------------------------------------------------------------------------
  [PASS] detection=MATCH     expected=True   -- Malicious: attacker requesting RC4 TGS...
  [PASS] detection=no-match  expected=False  -- Benign: normal AES256 TGS request...
...
RESULTS: 19/19 log entries scored as expected
```

This is the "before/after" proof that each rule actually works, not just a
static YAML file that's never been run against real-shaped data.

## About the Validator

`validate_rules.py` is a **lightweight, dependency-minimal reference
matcher** written specifically for this repo - it is not a replacement for
a real Sigma backend. It implements the subset of Sigma syntax the rules
here use (`|contains`, `|endswith`, `|gte`, and `and`/`or`/`not`
conditions). For production use, convert these rules with the official
[pySigma](https://github.com/SigmaHQ/pySigma) toolchain into your SIEM's
native query language (Splunk SPL, Elastic EQL/KQL, Microsoft Sentinel
KQL, etc.).

## Rule Design Philosophy

Every rule in this repo ships with:
- A `references` section pointing to the ATT&CK technique and a technical
  writeup used while researching the behavior
- A `falsepositives` section documenting realistic sources of noise
  (an intentionally-triggered example is included in
  `dns_tunneling_sample.json`, showing how legitimate SPF/TXT lookups
  need tuning before production deployment)
- A `level` (severity) reflecting how actionable/urgent a true positive is
- ATT&CK tags in the `tags` field for SIEM/SOAR integration

## Extending This Lab

To add rule #6:
1. Write the Sigma YAML in `rules/`.
2. Add a sample log file in `sample_logs/` with at least one true-positive
   and one true-negative entry, each labeled `expected_detection`.
3. Register the pair in `RULE_LOG_PAIRS` in `validator/validate_rules.py`.
4. Add a row to `docs/attack_mapping.md`.

## Roadmap / Known Gaps

- Lateral movement rules (SMB/WMI/PsExec abuse) - planned v2
- Cloud-native detections (Azure AD / AWS IAM) - not yet covered
- Integration example with real Sigma → Splunk/Elastic conversion via
  pySigma

## Author

Kamal Ashraf (handle: `0xb7r`) - Computer Science student focused on
cybersecurity, pentesting, and detection engineering.
