# Harsh
import os
import json
import time
import re
import subprocess
from pprint import pprint
import cve_searchsploit as CS
from Wappalyzer import Wappalyzer, WebPage
import warnings
import boto3
import requests
import API_Handler as handler
warnings.filterwarnings("ignore", message="""Caught 'unbalanced parenthesis at position 119' compiling regex""", category=UserWarning )

autopilot = True

# located in this folder
base_folder = "~/RTF"

blacklist = ["bit.ly","awstrack.me"]


def init():
    os.system("mkdir Aquatone")
    os.system("mkdir Subdomains")
    os.system("mkdir CVE_Search")
    os.system("mkdir CVE_Search/Cache")
    os.system("mkdir Js_Links")
    os.system("mkdir Nuclei")
    os.system("mkdir Wig")
    os.system("mkdir Nmap")
    os.system("mkdir Wappalyzer")
    return

def exec_sublister(domain_name):
    os.system("touch Subdomains/sublist3r_results.txt")
    process = subprocess.Popen([f"sublist3r -d {domain_name} -o Subdomains/sublist3r_results.txt"],shell=True)
    process.wait()
    return

def exec_subfinder(domain_name):
    process = subprocess.Popen([f"subfinder -d {domain_name} -silent -o Subdomains/subfinder_results.txt"],shell=True)
    process.wait()
    return

def exec_assetfinder(domain_name):
    process = subprocess.Popen([f"assetfinder {domain_name} > Subdomains/assetfinder_results.txt"],shell = True)
    process.wait()
    return


def subdomain_enumeration(domain_name,store = False):

    exec_sublister(domain_name)
    exec_subfinder(domain_name)
    exec_assetfinder(domain_name)

    with open("Subdomains/sublist3r_results.txt","r") as f:
        sublist3r_data = f.read().splitlines()
    with open("Subdomains/subfinder_results.txt","r") as f:
        subfinder_data = f.read().splitlines()
    with open("Subdomains/assetfinder_results.txt","r") as f:
        assetfinder_data = f.read().splitlines()

    subdomain_list = list(set(sublist3r_data + subfinder_data + assetfinder_data))
    for subdomain in subdomain_list:
        for x in blacklist:
            if x in subdomain:
                subdomain_list.remove(subdomain)

    if not store:
        with open(f"Subdomains/{domain_name}_subdomain_results.txt","w") as f:
            f.write("\n".join(i for i in subdomain_list))
    else:
        with open(f"Subdomains/temp_subdomain_results.txt","w") as f:
            f.write("\n".join(i for i in subdomain_list))

    os.system(f"rm Subdomains/sublist3r_results.txt")
    os.system(f"rm Subdomains/subfinder_results.txt")
    os.system(f"rm Subdomains/assetfinder_results.txt")

    return subdomain_list

def recursive_enum(domain_name,subdomain_list,iter=1):
    for _ in range(iter):
        newly_found_subdomains_list = []
        for i,subdomain in enumerate(subdomain_list):
            if subdomain in blacklist:
                continue
            newly_found_subdomains = subdomain_enumeration(subdomain,store=True)
            if len(newly_found_subdomains) == 1:
                print(f"No subdomains found for {subdomain} | ({i+1}/{len(subdomain_list)})")
                print()
                continue
            print(f"Subdomains found for {subdomain} | ({i+1}/{len(subdomain_list)}) :")
            print(newly_found_subdomains,len(newly_found_subdomains))
            print()
            newly_found_subdomains_list += newly_found_subdomains

        subdomain_list = list(set(subdomain_list+newly_found_subdomains_list))

    with open(f"Subdomains/{domain_name}_subdomain_results.txt","w") as f:
        f.write("\n".join(i for i in subdomain_list))
    return subdomain_list

 
def exec_aquatone(domain_name):
    if not autopilot:
        print("Would you like to run Aquatone to get screenshots? (This may take a while)")
        x = input("Yes/No:")
        if x not in ["y","Y","yes","Yes"]:
            return

    os.system(f"mkdir Aquatone/{domain_name}")
    try:
        process = subprocess.Popen([f"cat Subdomains/{domain_name}_subdomain_results.txt | aquatone -out Aquatone/{domain_name}"],shell=True)
        process.wait()
        print("Aquatone scan completed.\n")
    except Exception as e:
        print(f"Error executing Aquatone: {e}")
        print("Moving on to the next function.\n")

 
    return 

def exec_httprobe(domain_name):
    os.system(f"touch Subdomains/{domain_name}_livedomain_results.txt")
    result = subprocess.check_output([f"cat Subdomains/{domain_name}_subdomain_results.txt | httprobe"],shell = True)
    data = result.decode().strip().splitlines()

    with open(f"Subdomains/{domain_name}_livedomain_results.txt","w") as f:
        f.write("\n".join(i for i in data))
    return data

def exec_linkfinder(domain_name):
    print("---------PASS 1---------")
    if not autopilot:
        print("Would you like to run Linkfinder to conduct JS File Recon? (This may take a while)")
        x = input("Yes/No:")
        if x not in ["y","Y","yes","Yes"]:
            return
    
    
    print("---------PASS 2---------")
    try:

        print("---------PASS 3---------")
        print(f"DOMAINN {domain_name}")
        with open(f"Subdomains/{domain_name}_livedomain_results.txt") as f:
            data = f.read().split("\n")
            print("IN TRY:", data)
    except:
        data = exec_httprobe(domain_name)
        print("EXCEPTION:", data)

    js_links = []
    pprint(data)
    os.system(f"mkdir Js_Links/{domain_name}_cache")
    for i,subdomain in enumerate(data):
        print('SUBDOAMIN IZ', i, subdomain)
        r = subprocess.check_output([f"python3 /opt/LinkFinder/linkfinder.py -i {subdomain} -d -o cli"],shell=True).decode("utf-8")
        print("FINAL PASS HERE NO ERRORS")
        # regex to find links in js text
        regex=r"\b((?:https?://)?(?:(?:www\.)?(?:[\da-z\.-]+)\.(?:[a-z]{2,6})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))(?::[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?(?:/[\w\.-]*)*/?)\b"

        links = (re.findall(regex, r))
        print(f"JS Links found for {subdomain} | ({i+1}/{len(data)}) :")
        print(links,len(links))
        print()
        
        if "https://" in subdomain:
            subdomain = subdomain.replace("https://","")
        else:
            subdomain = subdomain.replace("http://","")
        with open(f"Js_Links/{domain_name}_cache/{subdomain}_linkfinder_results.txt","w") as f:
            f.write("\n".join(i for i in set(links)))
        js_links += links

    js_links = list(set(js_links))
    print(js_links,len(js_links))
    os.system(f"touch Js_Links/{domain_name}_linkfinder_results.txt")
    with open(f"Js_Links/{domain_name}_linkfinder_results.txt","w") as f:
        f.write("\n".join(i for i in js_links))
    return 

def exec_nuclei(domain_name):
    if not autopilot:
        print("Would you like to run Nuclei for Vulnerability Assesment? (This may take a while)")
        x = input("Yes/No:")
        if x not in ["y","Y","yes","Yes"]:
            return
    os.system(f"touch Nuclei/{domain_name}_nuclei_results.json")
    try:
        process = subprocess.Popen([f"nuclei -l Subdomains/{domain_name}_subdomain_results.txt  -s critical,high,medium,low -j -o Nuclei/{domain_name}_nuclei_results.json"],shell=True)
        process.wait()
        print("Nuclei scan completed")
    except Exception as e:
        print(f"Error executing nuclie: {e}")
        print("Moving on to the next function.\n")
    return
    

def exec_wig(domain_name):
    if not autopilot:
        print("Would you like to run Wig for finding CMS information? (This may take a while)")
        x = input("Yes/No:")
        if x not in ["y","Y","yes","Yes"]:
            return

    with open(f"Subdomains/{domain_name}_subdomain_results.txt","r") as f:
        subdomain_list = f.read().splitlines()

    os.system(f"mkdir Wig/{domain_name}_cache")
    for i,subdomain in enumerate(subdomain_list):
        print(f"Scanning for {subdomain} | {i+1}/{len(subdomain_list)}")
        output_path= f"""Wig/{domain_name}_cache/{subdomain}_json"""
        stop_after = 100
        threads = 80
        final_wig_command = f"wig -n {stop_after} -w {output_path} -t {threads} {subdomain}"
        process = subprocess.Popen([final_wig_command], shell=True)
        process.wait()
        print("Wig scan completed")
        
    final_output = {}
    for subdomain in subdomain_list:
        print("THIS IS THE LATEST FILE")
        try:
            with open(f"Wig/{domain_name}_cache/{subdomain}_json.json","r") as f:
                subdomain_json = json.loads(f.read())[0]
        # except FileNotFoundError as e:
        except Exception as e:
            print(f"Error : {e}")
            print("Moving on to the next function.\n")
            return  # Return or continue to move to the next funct  ion
        
        if "data" not in subdomain_json or "error" in subdomain_json["site_info"]:
            pass
        else:
            req_json = {"data":[]}
            for info in subdomain_json["data"]:
                if info["category"] != "subdomain":
                    req_json["data"].append(info)
            final_output[subdomain] = req_json["data"]
    
    with open(f"Wig/{domain_name}_wig_results.json" , "w+") as f:
        json.dump(final_output,f)
    print("Wig completed")

def exec_wappalyzer(domain_name):
    if not autopilot:
        print("Would you like to run Wappalyzer for finding technology stack of subdomains? (This may take a while)")
        x = input("Yes/No:")
        if x not in ["y","Y","yes","Yes"]:
            return

    with open(f"Subdomains/{domain_name}_livedomain_results.txt","r") as f:
        subdomain_list = f.read().splitlines()

    final_results = {}
    wappalyzer = Wappalyzer.latest()
    for i,subdomain in enumerate(subdomain_list):
        print(f"Scanning for {subdomain} | {i+1}/{len(subdomain_list)}")
        if subdomain in final_results.keys():
            continue
        try:
            webpage = WebPage.new_from_url(subdomain)
        except:
            continue
        result = wappalyzer.analyze_with_cpe_and_version(webpage)
        print(result)
        if result is None:
            continue
        final_results[subdomain] = result
        print(final_results[subdomain])

    with open(f"Wappalyzer/{domain_name}_wappalyzer_results.json","w+") as f:
        json.dump(final_results,f)
    print("Wappalyzer completed.\n")
    return

def exec_nmap(domain_name):
    if not autopilot:
        print("Would you like to run Nmap for finding port scan of subdomains? (This may take a while)")
        x = input("Yes/No:")
        if x not in ["y","Y","yes","Yes"]:
            return

    with open(f"Subdomains/{domain_name}_subdomain_results.txt","r") as f:
        subdomain_list = f.read().splitlines()
    os.system(f"mkdir Nmap/{domain_name}")
    for i,subdomain in enumerate(subdomain_list):
        print(f"Scanning for {subdomain} | {i+1}/{len(subdomain_list)}")
        process = subprocess.Popen([f"nmap -sV {subdomain} -oN Nmap/{domain_name}/{subdomain}_portscan_results.txt"],shell = True)
        process.wait()

    return

def parse_wappalyzer_results(domain_name):
    with open(f"Wappalyzer/{domain_name}_wappalyzer_results.json") as f:
        data = json.load(f)
    all_found_cpes = {}
    for subdomain in data.keys():
        if subdomain not in all_found_cpes:
            all_found_cpes[subdomain] = []
        subdomain_technologies = data[subdomain]
        for tech in subdomain_technologies.keys():
            if "CPEs" in subdomain_technologies[tech].keys():
                for cpe in subdomain_technologies[tech]["CPEs"]:
                    all_found_cpes[subdomain].append(cpe)
    # print(all_found_cpes)
    return all_found_cpes




def get_cves_for_cpe(cpe):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"

    try:
        response = requests.get(url, headers=headers)
        while response.status_code == 503:
            time.sleep(6)
            response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            cve_ids = [vuln["cve"]["id"] for vuln in data["vulnerabilities"]]
            return cve_ids
        elif response.status_code == 403:
            print("Access to the API is forbidden by administrative rules. Please check any restrictions or rate limits.")
        else:
            print(f"Error: {response.status_code} - {response.text}")

    except requests.exceptions.ConnectionError as e:
        print(f"Connection error for CPE: {cpe}. Moving on to the next CPE.")
    
    return []

def save_cve_results_to_file(cpe, cve_ids):
    cpe_filename = cpe.replace(":", "_")
    with open(f"CVE_Search/Cache/{cpe_filename}_cve_search_results.txt", "w") as f:
        for cve_id in cve_ids:
            f.write(f"CVE: {cve_id}\n")

def exec_cve_search(domain_name):
    CS.update_db()
    data = parse_wappalyzer_results(domain_name)
    cve_results = {}

    for i,subdomain in enumerate(data.keys()):
        print(f"Extracting CVE's for {subdomain} | {i+1}/{len(data.keys())}")
        if subdomain not in cve_results.keys():
            cve_results[subdomain] = {}
        cpe_list = data[subdomain]
        # print(cpe_list)
        for cpe in cpe_list:
            time.sleep(8)  # To avoid overloading the API
            cve_ids = get_cves_for_cpe(cpe)  # Replace with your function to get CVE IDs
            if cve_ids:
                save_cve_results_to_file(cpe, cve_ids)
                print(f"Saved CVEs for {cpe} in {cpe.replace(':', '_')}_cve_search_results.txt")
            else:
                cpe_filename = cpe.replace(":", "_")
                with open(f"CVE_Search/Cache/{cpe_filename}_cve_search_results.txt", "w") as f:
                    print(f"No CVEs found for {cpe}, created blank file {cpe_filename}_cve_search_results.txt")
            # Insert path to cve-search here
            # process = subprocess.Popen([f"/home/kali/Documents/cve-search/bin/search.py -p {cpe} > CVE_Search/Cache/{cpe_filename}_cve_search_results.txt"],shell=True)
            # process.wait()


    for subdomain in data.keys():
        cpe_list = data[subdomain]
        for cpe in cpe_list:
            cves_found = parse_cve_search_results(cpe)
            # print(cves_found)
            edbids_found = []
            for cve in cves_found:
                # print(cve)
                edbid = get_edbid_from_cve(cve)
                # print(edbid)
                edbids_found += edbid
                # print(edbids_found)

            cve_results[subdomain].update({cpe:{"CVEs":cves_found,"EDBIDs":edbids_found}})
            # print(cve_results[subdomain])
            

    with open(f"CVE_Search/{domain_name}_CVE_results.json","w+") as f:
        json.dump(cve_results,f)
    return

def parse_cve_search_results(cpe_name):
    cpe_filename = cpe_name.replace(":", "_")
    with open(f"CVE_Search/Cache/{cpe_filename}_cve_search_results.txt") as f:
        data = f.readlines()
# Parses data from txt
    CVE_list = []
    for line in data:
        if "CVE: " in line:
            CVE_list.append(line.replace("CVE: ","").strip())
        else:
            pass
    # print(CVE_list)
    return CVE_list

def get_edbid_from_cve(cve):
    x = CS.edbid_from_cve(cve)
    # print(x)
    return x

def upload_directory_to_s3(bucket_name, local_directory, s3_prefix):
    s3 = boto3.client('s3')
    for root, dirs, files in os.walk(local_directory):
        for file in files:
            local_path = os.path.join(root, file)
            relative_path = os.path.relpath(local_path, local_directory)
            s3_path = os.path.join(s3_prefix, relative_path).replace("\\", "/")
            s3.upload_file(local_path, bucket_name, s3_path)
            print(f"Uploaded '{local_path}' to 's3://{bucket_name}/{s3_path}'")
bucket_name = "<changethis>"
local_directory = "/opt/results"
s3_prefix = f"<changethis>/{os.environ['DOMAIN']}_results"

def Run_Tool(domain_name):
    init()
    subdomain_list = subdomain_enumeration(domain_name)
    recursive_enum(domain_name,subdomain_list)
    exec_aquatone(domain_name)
    exec_httprobe(domain_name)
    exec_linkfinder(domain_name)
    exec_nuclei(domain_name)
    exec_wig(domain_name)
    exec_nmap(domain_name)
    exec_wappalyzer(domain_name)
    exec_cve_search(domain_name)
    upload_directory_to_s3(bucket_name, local_directory, s3_prefix)
    handler.getDomainInfo(domain_name)
    handler.subdomain()
    return

Run_Tool(os.environ['DOMAIN'])
