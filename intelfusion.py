
import os
import requests

def enrich_with_abuseipdb(ioc):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "Missing AbuseIPDB API key."}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()["data"]
        return {
            "Abuse Score": data.get("abuseConfidenceScore"),
            "Total Reports": data.get("totalReports"),
            "Country": data.get("countryCode"),
            "ISP": data.get("isp"),
            "Domain": data.get("domain"),
            "Last Reported": data.get("lastReportedAt")
        }
    except Exception as e:
        return {"error": f"AbuseIPDB Error: {str(e)}"}

def enrich_with_otx(ioc):
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        return {"error": "Missing OTX API key."}
    headers = {"X-OTX-API-KEY": api_key}
    try:
        response = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general", headers=headers)
        data = response.json()
        return {
            "Pulse Count": data.get("pulse_info", {}).get("count"),
            "TLP": data.get("pulse_info", {}).get("TLP"),
            "First Seen": data.get("first_seen"),
            "Last Seen": data.get("last_seen"),
            "ASN": data.get("asn"),
            "Country": data.get("country_name")
        }
    except Exception as e:
        return {"error": f"OTX Error: {str(e)}"}

def run_intelfusion(ioc):
    return {
        "AbuseIPDB": enrich_with_abuseipdb(ioc),
        "AlienVault OTX": enrich_with_otx(ioc)
    }
