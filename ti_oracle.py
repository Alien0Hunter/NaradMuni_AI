import os
import requests

VT_API_KEY = os.getenv("VT_API_KEY")

def lookup_ioc(ioc):
    headers = {
        "x-apikey": VT_API_KEY
    }

    if "." in ioc and not ioc.startswith("http"):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc.startswith("http") or "." in ioc:
        url = f"https://www.virustotal.com/api/v3/urls/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {"error": f"Error {response.status_code}: {response.text}"}

    data = response.json()
    try:
        attributes = data["data"]["attributes"]
        last_analysis_stats = attributes["last_analysis_stats"]
        threat_label = attributes.get("meaningful_name", "N/A")
        reputation = attributes.get("reputation", "N/A")
        return {
            "label": threat_label,
            "reputation": reputation,
            "malicious": last_analysis_stats.get("malicious", 0),
            "suspicious": last_analysis_stats.get("suspicious", 0),
            "harmless": last_analysis_stats.get("harmless", 0),
            "undetected": last_analysis_stats.get("undetected", 0)
        }
    except Exception as e:
        return {"error": str(e)}
