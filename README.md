# IOC Enrichment Tool

A Python CLI tool that checks IP addresses against the AbuseIPDB API and returns abuse confidence score, ISP, country, and report history. Supports single IP lookups and batch processing from a file, with results exported to CSV.

## Features
- Checks IP reputation via AbuseIPDB API
- Single IP or batch mode (reads IPs from any user-specified text file)
- Validates IP format before making API calls (saves API quota)
- Handles invalid input, missing files, and network errors gracefully
- Exports results to a CSV report
- Uses environment variables for API key.

## Setup

1. Clone the repo
2. Install dependencies: pip install -r requirements.txt
3. Get a free AbuseIPDB API key: https://www.abuseipdb.com/register
4. Set it as an environment variable: export ABUSEIPDB_KEY="your_key_here"
5. Run the tool: python3 IOC.py


## Usage

Choose single or batch mode when prompted: Check a single IP or a batch from file? (single/batch): single
Enter an ip address to check: 8.8.8.8
<<<<<<< HEAD
IP: 8.8.8.8

Abuse Score: 0

Country: US

ISP: Google LLC

Total Reports: 123
=======

or for batch mode, provide a text file with one IP per line: Check a single IP or a batch from file? (single/batch): batch
Enter the filename containing IPs; 


Results print to the terminal and are saved to `report.csv`.
>>>>>>> 18b09e4 (Add batch mode with custom filename, IP validation, and CSV export)

## Roadmap
- Add domain and file hash enrichment
- Markdown report export
- Multi-source enrichment 
