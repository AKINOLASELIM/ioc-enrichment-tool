import os
import requests
import ipaddress
import csv

abuseipdb_key = os.environ.get("ABUSEIPDB_KEY")
virustotal_key = os.environ.get("VIRUSTOTAL_KEY")

abuse_url = "https://api.abuseipdb.com/api/v2/check"
abuse_headers = {
    "Key": abuseipdb_key,
    "Accept": "application/json"
}

vt_headers = {
    "x-apikey": virustotal_key
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
        response = requests.get(abuse_url, params=params, headers=abuse_headers, timeout=5)
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
            return ["IP", ip_info["ipAddress"], ip_info["abuseConfidenceScore"], ip_info["countryCode"], ip_info["isp"], ip_info["totalReports"]]
    except requests.exceptions.Timeout:
        print("Request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("Could not connect to AbuseIPDB")
        return None

def check_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        response = requests.get(url, headers=vt_headers, timeout=5)
        data = response.json()
        if "error" in data:
            print("Error:", data["error"]["message"])
            return None
        else:
            attributes = data["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            print("Domain:", domain)
            print("Malicious:", stats["malicious"])
            print("Suspicious:", stats["suspicious"])
            print("Harmless:", stats["harmless"])
            print("Reputation:", attributes["reputation"])
            return ["Domain", domain, stats["malicious"], stats["suspicious"], stats["harmless"], attributes["reputation"]]
    except requests.exceptions.Timeout:
        print("Request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("Could not connect to VirusTotal")
        return None


results = []

ioc_type = input("Check an IP or a domain? (ip/domain): ").strip().lower()

if ioc_type == "ip":
    mode = input("Single or batch? (single/batch): ").strip().lower()

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

elif ioc_type == "domain":
    mode = input("Single or batch? (single/batch): ").strip().lower()

    if mode == "single":
        domain_to_check = input("Enter a domain to check: ").strip()
        row = check_domain(domain_to_check)
        if row:
            results.append(row)

    elif mode == "batch":
        filename = input("Enter the filename containing domains: ").strip()
        try:
            with open(filename, "r") as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        print("-------------------------")
                        row = check_domain(domain)
                        if row:
                            results.append(row)
        except FileNotFoundError:
            print("File not found. Check the filename and try again.")
    else:
        print("Invalid choice. Please enter 'single' or 'batch'.")

else:
    print("Invalid choice. Please enter 'ip' or 'domain'.")


if results:
    with open("report.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Type", "Indicator", "Metric1", "Metric2", "Metric3", "Metric4"])
        writer.writerows(results)
    print("Results saved to report.csv")
