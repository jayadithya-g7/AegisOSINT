# AEGIS-OSINT FORENSIC INVESTIGATION REPORT

**Case ID**: `INV-1791959743`  
**Target Subject**: `paypal-security-alert-center.com`  
**Victim Brand**: `PayPal`  
**Risk Rating**: `100.0/100` (CRITICAL)  
**Timestamp UTC**: `2026-10-14T06:36:02.631858+00:00`  

## Executive Summary

On 2026-10-14, the AegisOSINT automated cyber threat intelligence system identified an active brand impersonation and online fraud campaign targeting 'PayPal'. The subject 'paypal-security-alert-center.com' demonstrates a composite risk rating of 100.0/100 (CRITICAL). Multi-vector analysis confirmed infrastructure deceptive staging, visual brand mimicry, and coordinated link correlation.

## Indicators of Compromise (IoCs)

- **Domains**: paypal-security-alert-center.com
- **Ip Addresses**: 
- **Phone Numbers**: +1-800-443-2679
- **Email Addresses**: billing-verification@gmail.com
- **Crypto Wallets**: 0x71C8364741369796e95c1BEEf0bA24eE275817E1

## Active Defense Signatures

### DNS RPZ Sinkhole Rule
```text
; AegisOSINT / CyberSecEval Sinkhole Policy for PayPal Impersonation
paypal-security-alert-center.com CNAME .
*.paypal-security-alert-center.com CNAME .
; Redirect to security sinkhole:
; paypal-security-alert-center.com A 0.0.0.0
```

### Suricata IDS Signature
```text
alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"AEGIS-CTI [GLM-5.3 Verified] Brand Impersonation Beacon to paypal-security-alert-center.com"; dns.query; content:"paypal-security-alert-center.com"; nocase; classtype:trojan-activity; sid:1664712; rev:1; metadata:created_at 2026_10_14, target_brand "PayPal", confidence_level high;)
```

### Cloudflare WAF Filter Expression
```text
(http.host eq "paypal-security-alert-center.com") or (http.request.uri.query contains "paypal-security-alert-center.com") or (lower(http.request.body) contains "paypal" and not ssl)
```

### Sigma SIEM Detection Rule
```yaml
title: Potential Network Connection to PayPal Impersonation Domain
id: 9b5867e0-fb7f-5ff9-9f7f-1a9602d03040
status: experimental
description: Detects endpoint DNS lookup or network beaconing to confirmed brand impersonation domain paypal-security-alert-center.com
references:
    - https://attack.mitre.org/techniques/T1566/002/
author: AegisOSINT CTI Defense Engine
date: 2026/10/14
logsource:
    category: dns
    product: windows
detection:
    selection:
        query_name|contains: 'paypal-security-alert-center.com'
    condition: selection
falsepositives:
    - Legitimate administrative investigation
level: high
tags:
    - attack.initial_access
    - attack.t1566.002
    - attack.t1656
```

### YARA Rule
```yara
rule Phishing_Kit_PayPal_paypal_security_alert_center_com {
    meta:
        description = "Detects web phishing kits or email lures mimicking PayPal"
        author = "AegisOSINT CTI Rule Engine"
        reference = "MITRE ATT&CK T1566.002"
        threat_level = "High"
        date = "2026/10/14"
    strings:
        $target_domain = "paypal-security-alert-center.com" ascii wide nocase
        $brand_name = "PayPal" ascii wide nocase
        $lure_phrase1 = "verify your account" ascii wide nocase
        $lure_phrase2 = "account suspended" ascii wide nocase
        $lure_phrase3 = "confirm your identity" ascii wide nocase
        $lure_phrase4 = "unauthorized login attempt" ascii wide nocase
    condition:
        $target_domain or ($brand_name and 1 of ($lure_phrase*))
}
```

## Forensic Evidence Chain of Custody

- **ID**: `dca05071-ea2b-43ba-b757-4ebfa27d91bd` | **Type**: `DOMAIN_TELEMETRY_SNAPSHOT` | **SHA-256**: `b295818a5b6864c601d1e134c1fa8f9675b4a78db429c3290a5cdde1e9f8b71b`
- **ID**: `6e57abed-ed14-45cc-b578-39976e83b3e3` | **Type**: `TELECOM_FRAUD_RECORD` | **SHA-256**: `d3c6baef0dc90db727422cfa10d5e7927785f8826fb786c14a2f5339db6411ce`
- **ID**: `866958a9-e5e9-4d20-8cb6-8fa46254bc88` | **Type**: `PHISHING_LURE_NLP_RECEIPT` | **SHA-256**: `724014bbc800f53adf4301c1de4ba998a40e9d7abf31ffe5edeab9c8a464807b`
