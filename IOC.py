import os
import requests

api_key = os.environ.get("ABUSEIPDB_KEY")
url = "https://api.abuseipdb.com/api/v2/check"
headers = {
    "Key": api_key,
    "Accept": "application/json"
}

def check_ip(ip):
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }

    try:
        response = requests.get(url, params=params, headers=headers, timeout=5)
        data = response.json()

        if "errors" in data:
            print("Error:", data["errors"][0]["detail"])
        else:
            ip_info = data["data"]
            print("IP:", ip_info["ipAddress"])
            print("Abuse Score:", ip_info["abuseConfidenceScore"])
            print("Country:", ip_info["countryCode"])
            print("ISP:", ip_info["isp"])
            print("Total Reports:", ip_info["totalReports"])

    except requests.exceptions.Timeout:
        print("Request timed out")
    except requests.exceptions.ConnectionError:
        print("Could not connect to AbuseIPDB")


ip_to_check = input("Enter an ip address to check: ").strip()
check_ip(ip_to_check)
