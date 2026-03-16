# RTeamF
Developed an automated domain scanning tool that integrates subdomain discovery, vulnerability detection, and technology stack identification, with results securely stored in AWS S3 and MongoDB.

## Overview
This tool is designed to streamline the process of discovering subdomains, identifying open ports, and detecting known vulnerabilities across target domains. It integrates several powerful tools to automate and enhance the security assessment process, providing comprehensive insights into the security posture of a domain.

## Key Features
* **Asynchronous Tool Orchestration:** Replaces sequential blocking execution with `asyncio`. Tasks like Nuclei, Nmap, Aquatone, and LinkFinder execute concurrently in a non-blocking asynchronous event loop, significantly accelerating scan durations over large attack surfaces.
* **Smart Rate-Limiting:** Implements a dynamic Token-Bucket rate-limiting algorithm for the public NIST NVD API (adjusting smoothly for deployments passing an `NVD_API_KEY`), removing hardcoded sleep timers and preventing 403 blocks.
* **Corroborative False-Positive Filtering:** Automatically correlates Nuclei vulnerability findings against open ports (verified by Nmap) and live technology stacks (verified by Wappalyzer). Findings mapped to closed ports or absent technologies are rigorously down-scored to silence noise and elevate actionable intelligence.
* **Subdomain Discovery:** Uses Sublist3r, Subfinder, and Assetfinder to uncover subdomains associated with a target domain comprehensively.
* **Live Domain Checks:** Employs Httprobe to filter dead endpoints and resolve active domains.
* **JavaScript Reconnaissance:** Integrates LinkFinder to crawl live properties and extract hidden endpoints via regex.
* **Open Port Scanning:** Utilizes Nmap (`-sV`) for thorough port mapping and service fingerprinting.
* **Vulnerability Detection:** Employs Nuclei with specific templates to detect known misconfigurations and severe vulnerabilities.
* **Technology Profiling:** Leverages Wappalyzer & wig to detect underlying CMS, frameworks, and backend tech stacks.
* **CWE and CVE Mapping:** Extracts known product versions and retrieves Common Vulnerabilities and Exposures (CVEs) and associate Exploit-DB entries via `cve_searchsploit`.
* **Standardized JSON Analytics Engine:** Normalizes unstructured terminal text blobs into deeply structured API endpoints (`API.py`), providing an immediate algorithmic "Risk Posture" score per target domain.
* **Secure Data Storage:** Raw scan directories are pushed asynchronously to AWS S3, while the structured contextual JSON is persisted in an external MongoDB (`cloudRTF`) database.
