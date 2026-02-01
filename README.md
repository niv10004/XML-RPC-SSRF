# XML-RPC-SSRF
WordPress XML-RPC SSRF Exploitation Tool -  Automated Blind SSRF Testing

Author: Niv Hillel
Version: 1.0
Language: Python 3

Overview

This tool detects and validates Blind Server-Side Request Forgery (SSRF) vulnerabilities in WordPress sites that expose the xmlrpc.php endpoint with the pingback.ping method enabled.

It is designed for authorized security testing, research, and vulnerability validation only.

Legal Disclaimer

This tool must only be used on systems you own or have explicit permission to test.
Unauthorized use is illegal. The author assumes no responsibility for misuse.

Features

XML-RPC availability check

pingback.ping method detection

Automated WordPress post discovery

Blind SSRF confirmation via webhook callbacks

Optional internal port probing (blind)

Verbose and non-verbose modes

Requirements

Python 3.8+

requests, urllib3

Install dependencies:

pip install requests urllib3

Installation
git clone https://github.com/<your-username>/wp-xmlrpc-ssrf-tool.git
cd wp-xmlrpc-ssrf-tool
chmod +x wp_xmlrpc_ssrf.py

Usage

Basic check:

python3 wp_xmlrpc_ssrf.py -t https://target.com


Automated SSRF test:

python3 wp_xmlrpc_ssrf.py -t https://target.com --auto


Custom webhook:

python3 wp_xmlrpc_ssrf.py -t https://target.com -w https://webhook.site/<uuid>


Specific post:

python3 wp_xmlrpc_ssrf.py -t https://target.com -p https://target.com/post/


Port scan (blind):

python3 wp_xmlrpc_ssrf.py -t https://target.com --ports 80,443,3306


Full test:

python3 wp_xmlrpc_ssrf.py -t https://target.com --full -v

Output

VULNERABLE – SSRF confirmed

No callback – Outbound traffic blocked

XML-RPC disabled – Not vulnerable

Notes

This tool performs non-destructive testing only and does not execute commands or modify server state
