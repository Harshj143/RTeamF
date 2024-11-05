# RTeamF
Developed an automated domain scanning tool that integrates subdomain discovery, vulnerability detection, and technology stack identification, with results securely stored in AWS S3 and MongoDB.

Overview
This tool is designed to streamline the process of discovering subdomains, identifying open ports, and detecting known vulnerabilities across target domains. It integrates several powerful tools to automate and enhance the security assessment process, providing comprehensive insights into the security posture of a domain.

Features
Subdomain Discovery: Uses Sublist3r, Subfinder, and Assetfinder to uncover subdomains associated with a target domain efficiently.
Live Domain Checks: Employs Httprobe to verify the live status of discovered domains.
JavaScript Link Extraction: Integrates LinkFinder and regular expressions to extract and analyze JavaScript links, aiding in further reconnaissance.
Open Port Scanning: Utilizes Nmap to scan for open ports, providing insights into the network exposure of a domain.
Vulnerability Detection: Uses Nuclei to identify known vulnerabilities by scanning for specific patterns and weaknesses.
Technology Stack Identification: Leverages Wappalyzer to detect technologies used by the target domain, including frameworks, libraries, and server details.
CWE and CVE Retrieval: Maps detected issues to Common Weakness Enumerations (CWEs) and Common Vulnerabilities and Exposures (CVEs) for standardized reporting and mitigation guidance.
Automated Workflow: The entire scanning process is automated, from discovery to reporting.
Secure Data Storage: Results are securely stored in AWS S3 and MongoDB for easy access and further analysis.
