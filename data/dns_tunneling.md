# DNS Tunneling Threat Hunt

## Description:
DNS tunneling uses DNS queries and responses to pass data and commands to/from compromised systems.

## Indicators:
- Excessive TXT record lookups
- Unusual domain entropy
- DNS to single domain with high frequency

## Tools:
- Wireshark
- Bro/Zeek
- Splunk: `index=dns | stats count by query`