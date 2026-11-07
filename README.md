# threat-model-ThreatSurfaceScanner

A command-line tool that analyzes a target system (IP address, hostname, or domain) and identifies potential attack vectors based on open ports and service names from an `nmap -sV` scan. It parses the port, state, and service columns of nmap output, so the service name (for example ssh or http), not the last word of the version banner, drives the named checks for ftp, ssh, http, https, and msrdp. Other open services receive a generic note. Results can be exported as JSON or markdown without extra packages. PDF export uses markdown2 and wkhtmltopdf, and graphviz export uses the graphviz package; both are loaded only when that format is requested. A failed scan or a failed export exits non-zero and does not report completion.

## Install
`git clone https://github.com/ShadowGuard-AI/threat-model-threatsurfacescanner.git`

## Usage
`python3 main.py 127.0.0.1 -p 22,80,443 -o threat_model.json --format json`

## Parameters
- `target`: Target system to scan (IP address, hostname, or domain, required positional argument)
- `-h`: Show help message and exit
- `-p`: Comma-separated list of ports to scan (default: 21,22,80,443,3389)
- `-o`: Output file for the threat model (default: threat_model.json)
- `--format`: Output format: json, markdown, pdf, or graphviz (default: json)
- `--model-name`: Name of the threat model (default: default_model)

## License
MIT License. See LICENSE.
Copyright (c) ShadowGuard-AI
