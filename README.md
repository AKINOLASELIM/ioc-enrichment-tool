# IOC Enrichment Tool

A Python CLI tool that enriches indicators of compromise (IPs, domains) using AbuseIPDB and VirusTotal. Supports single or batch lookups, with results exported to CSV.

## Features
- IP reputation lookups via AbuseIPDB
- Domain reputation lookups via VirusTotal (malicious/suspicious/harmless engine counts, reputation score)
- Single IOC or batch mode (reads from any user-specified text file)
- Validates IP format before making API calls (saves API quota)
- Handles invalid input, missing files, and network errors gracefully
- Exports results to a CSV report
- Uses environment variables for API keys (never hardcoded)

## Setup

1. Clone the repo
2. Install dependencies: pip install -r requirements.txt
3. Get free API keys:
   - AbuseIPDB: https://www.abuseipdb.com/register
   - VirusTotal: https://www.virustotal.com/gui/join-us
4. Set them as environment variables: export ABUSEIPDB_KEY="your_key_here"
export VIRUSTOTAL_KEY="your_key_here"
5. Run the tool: python3 IOC.py

## Usage

Check an IP or a domain? (ip/domain): ip
Single or batch? (single/batch): single
Enter an ip address to check: 8.8.8.8

or

Check an IP or a domain? (ip/domain): domain
Single or batch? (single/batch): single
Enter a domain to check: google.com

Results print to the terminal and are saved to `report.csv`.

## Roadmap
- File hash enrichment (VirusTotal)
- Markdown report export
- Clearer CSV column structure per IOC type

