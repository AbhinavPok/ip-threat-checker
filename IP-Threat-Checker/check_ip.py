import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code != 200:
        print("Error checking IP")
        return None

    return response.json()

def get_risk_level(score):
    if score >= 80:
        return "HIGH RISK – Investigate or block"
    elif score >= 40:
        return "MEDIUM RISK – Monitor activity"
    elif score >= 10:
        return "LOW RISK – Log and review"
    else:
        return "NO KNOWN RISK"

if __name__ == "__main__":
    if not API_KEY:
        print("Missing API key. Add it to the .env file.")
        exit()

    ip = input("Enter an IP address to check: ").strip()

    data = check_ip(ip)
    if not data:
        exit()

    result = data["data"]
    score = result.get("abuseConfidenceScore", 0)

    print("\n--- IP Threat Report ---")
    print("IP Address:", result.get("ipAddress"))
    print("Abuse Score:", score)
    print("Total Reports:", result.get("totalReports"))
    print("Country:", result.get("countryCode"))
    print("ISP:", result.get("isp"))
    print("Risk Level:", get_risk_level(score))

    os.makedirs("output", exist_ok=True)
    filename = f"output/report_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

    print("\nReport saved to:", filename)
