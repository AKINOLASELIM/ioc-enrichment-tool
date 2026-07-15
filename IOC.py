import os
import requests
import ipaddress
import csv

api_key = os.environ.get("ABUSEIPDB_KEY")
url = "https://api.abuseipdb.com/api/v2/check"
headers = {
    "Key": api_key,
    "Accept": "application/json"
}

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

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
            return None
        else:
            ip_info = data["data"]
            print("IP:", ip_info["ipAddress"])
            print("Abuse Score:", ip_info["abuseConfidenceScore"])
            print("Country:", ip_info["countryCode"])
            print("ISP:", ip_info["isp"])
            print("Total Reports:", ip_info["totalReports"])
            return [ip_info["ipAddress"], ip_info["abuseConfidenceScore"], ip_info["countryCode"], ip_info["isp"], ip_info["totalReports"]]

    except requests.exceptions.Timeout:
        print("Request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("Could not connect to AbuseIPDB")
        return None


mode = input("Check a single IP or a batch from file? (single/batch): ").strip().lower()
results = []

if mode == "single":
    ip_to_check = input("Enter an ip address to check: ").strip()
    if is_valid_ip(ip_to_check):
        row = check_ip(ip_to_check)
        if row:
            results.append(row)
    else:
        print("That is not a valid IP address.")

elif mode == "batch":
    filename = input("Enter the filename containing IPs: ").strip()
    try:
        with open(filename, "r") as f:
            for line in f:
                ip = line.strip()
                if ip and is_valid_ip(ip):
                    print("-------------------------")
                    row = check_ip(ip)
                    if row:
                        results.append(row)
    except FileNotFoundError:
        print("File not found. Check the filename and try again.")

else:
    print("Invalid choice. Please enter 'single' or 'batch'.")

if results:
    with open("report.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Abuse Score", "Country", "ISP", "Total Reports"])
        writer.writerows(results)
    print("Results saved to report.csv")
