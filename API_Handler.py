from pprint import pprint
import os
import json
import pymongo


def get_severity_graph_data(nuclei_results):
    res = [0,0,0,0]
    for x in nuclei_results:
        if x == "":
            continue

        i = json.loads(x)
        if i["info"]["severity"] == "low":
            res[0] += 1
        elif i["info"]["severity"] == "medium":
            res[1] += 1
        elif i["info"]["severity"] == "high":
            res[2] += 1
        elif i["info"]["severity"] == "critical":
            res[3] += 1
    return res

def get_jslinks(subdomain):
    try:
        with open(f"Js_Links/{domain_name}_cache/{subdomain}_linkfinder_results.txt") as f:
            data = f.read().split("\n")
    except:
        return []
    return list(data)

def get_exploits_found(subdomain):
    exploits_found = []
    with open(f"CVE_Search/{domain_name}_CVE_results.json") as f:
        cve_search_data = json.load(f)
    try:
        cpe_json = cve_search_data[f"https://{subdomain}"]
        for cpe in cpe_json.keys():
            cve_exp_json = cpe_json[cpe]
            exploits_found += cve_exp_json["EDBIDs"]
    except:
        pass

    try:
        cpe_json = cve_search_data[f"http://{subdomain}"]
        for cpe in cpe_json.keys():
            cve_exp_json = cpe_json[cpe]
            exploits_found += cve_exp_json["EDBIDs"]
    except:
        pass

    return len(list(set(exploits_found)))

# def get_ip(subdomain):
#     try:
#         with open(f"Wig/{domain_name}_cache/{subdomain}_wig_results.json") as f:
#             data = json.load(f)
#     except:
#         return "N/A"
    
#     if data["site_info"]["ip"]:
#         return data["site_info"]["ip"]
    
#     return "N/A"

def get_ip(subdomain):
    try:
        with open(f"Wig/{domain_name}_cache/{subdomain}_json.json") as f:
            data = json.load(f)
    except:
        return "N/A"
    
    site_info = data[0]["site_info"]  # Extract the site_info dictionary from the list
    ip_list = site_info.get("ip", [])  # Get the list of IPs, default to an empty list if not present
    
    if ip_list:
        return ip_list
    else:
        return "N/A"


def get_wig_data(subdomain):
    try:
        with open(f"Wig/{domain_name}_cache/{subdomain}_wig_results.json") as f:
            return json.load(f)
    except:
        return []
       

# def get_openports(subdomain):
#     try:
#         with open(f"Nmap/{domain_name}/{subdomain}_portscan_results.txt") as f:
#             data = f.read()
#     except:
#         return []
#     data = data.splitlines()
#     req_data = []
#     switch = False
#     for line in data:
        
#         if switch:
#             req_data.append(line)

#         if "PORT    STATE SERVICE VERSION" in line:
#             switch = True

#         if "Service Info:" in line and switch:
#             switch = False
#             return req_data[:-1]
        
#         if "Service detection performed" in line and switch:
#             return req_data[:-2]
    
#     return []

def get_openports(subdomain):
    try:
        with open(f"Nmap/{domain_name}/{subdomain}_portscan_results.txt") as f:
            data = f.read()
    except FileNotFoundError:
        return []

    open_ports = []
    start_collecting = False

    for line in data.splitlines():
        if start_collecting:
            if not line.strip() or line.strip().startswith("Service Info") or "services unrecognized " in line or "service unrecognized" in line:
                break
            open_ports.append(line)
        elif line.startswith("PORT"):
            start_collecting = True
    
    if not open_ports:
        return []

    return open_ports

def get_vulns_found(subdomain):
    vulns_found = []
    with open(f"Nuclei/{domain_name}_nuclei_results.json") as f:
        nuclei_data = f.read().split("\n")
    for vuln in nuclei_data:
        if vuln == "":
            continue
        vuln = json.loads(vuln)
        if not "host" in vuln.keys():
            continue
        if vuln["host"] == subdomain and vuln.get("severity") != "info":     
            vulns_found.append(vuln)
    
    return vulns_found

def get_tech_found(subdomain):
    tech = []
    with open(f"Wappalyzer/{domain_name}_wappalyzer_results.json") as f:
        wapp_data = json.load(f)
    try:
        tech += wapp_data[f"https://{subdomain}"].keys()
    except:
        pass
    try:
        tech += wapp_data[f"http://{subdomain}"].keys()
    except:
        pass

    return list(set(tech))

def get_cves_found(subdomain):
    cves_found = []
    with open(f"CVE_Search/{domain_name}_CVE_results.json") as f:
        cve_search_data = json.load(f)
    try:
        cpe_json = cve_search_data[f"https://{subdomain}"]
        for cpe in cpe_json.keys():
            cve_exp_json = cpe_json[cpe]
            cves_found += cve_exp_json["CVEs"]
    except:
        pass
    
    try:
        cpe_json = cve_search_data[f"http://{subdomain}"]
        for cpe in cpe_json.keys():
            cve_exp_json = cpe_json[cpe]
            cves_found += cve_exp_json["CVEs"]
    except:
        pass
    return len(list(set(cves_found)))


def get_security_posture(json):
    # Define the numerical values for each input category
    input_values_mapping = {
        "1": 10,
        "2": 25,
        "3": 40,
        "4": 75,
        "5": 100
    }

    mapping = {
        "info": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5
    }

    # print(json)
    severity_list = []
    for vuln in json:
        severity_list.append(vuln["info"]["severity"])
    severity_list = [mapping[x] for x in severity_list]
    severity_list = sorted(severity_list, reverse=True)

    severity_temp = 0
    if len(severity_list) == 0:
        return 0
    factor = (1 / (len(severity_list)))
    for i, entries in enumerate(severity_list):
        if i == 0:
            if entries == 5:
                severity_temp = 100
                break
            severity_temp = input_values_mapping[str(entries)]
        else:
            severity_temp = severity_temp + ((3 / 4) * (100 - severity_temp) * (factor))
    return severity_temp

def getDomainInfo(domain):
    global domain_name
    domain_name = domain
    with open(f"Subdomains/{domain_name}_subdomain_results.txt") as f:
        subdomain_list = f.read()
    subdomain_list = subdomain_list.split("\n")

    with open(f"Js_Links/{domain_name}_linkfinder_results.txt") as f:
        data = f.read()
    links_found = data.split("\n")

    with open(f"Nuclei/{domain_name}_nuclei_results.json") as f:
        nuclei_results = f.read()

    nuclei_results = nuclei_results.split("\n")

        
    with open(f"Wig/{domain_name}_wig_results.json") as f:
        wig_results = json.loads(f.read())

    with open(f"CVE_Search/{domain_name}_CVE_results.json") as f:
        cve_search_data = json.load(f)

    with open(f"Wappalyzer/{domain_name}_wappalyzer_results.json") as f:
        wapp_data = json.load(f)

    exploits = []
    for subdomain in cve_search_data.keys():
        x = cve_search_data[subdomain]
        for i in x.keys():
            y = x[i]
            #if y["EDBIDs"] not in exploits:
            exploits += y["EDBIDs"]

    exploits = list(set(exploits))

    tech_list = []
    for subdomain in wapp_data.keys():
        x = wapp_data[subdomain]
        tech_list += x.keys()

    vuln_subdomains = []
    for subdomain in subdomain_list:
        if subdomain in str(nuclei_results):
            vuln_subdomains.append(subdomain)

    API1_json = {}
    API1_json.update({"domain_name":domain_name})
    API1_json.update({"total_subdomains":len(subdomain_list)})
    API1_json.update({"vulnerable_technologies":len(tech_list)})
    API1_json.update({"vulnerabilities_found":len(nuclei_results)})
    API1_json.update({"exploits_found":len(exploits)})
    API1_json.update({"vulnerable_subdomains":len(list(set(vuln_subdomains)))})
    API1_json.update({"severity_data": get_severity_graph_data(nuclei_results)})

    subdomain_data = []
    for i,subdomain_name in enumerate(subdomain_list):
            
            print(f"{i+1}/{len(subdomain_list)}")
            subdomain_json = {}
            jslinks = len(get_jslinks(subdomain_name))
            # print(jslinks)
            openports = len(get_openports(subdomain_name))
            # pprint(openports)
            vulns_found = len(get_vulns_found(subdomain_name))
            # pprint(vulns_found)
            tech_found = len(get_tech_found(subdomain_name))
            # print(tech_found)
            cves_found = get_cves_found(subdomain_name)
            # print(cves_found,len(cves_found))
            exploits_found = get_exploits_found(subdomain_name)
            # print(exploits_found)

            # updating the subdomain json

            subdomain_json.update({"subdomain_name":subdomain_name})
            subdomain_json.update({"js_links_count":jslinks})
            subdomain_json.update({"tech_found_count":tech_found})
            subdomain_json.update({"open_ports_count":openports})
            subdomain_json.update({"vulnerability_count":vulns_found})
            subdomain_json.update({"cve_count":cves_found})
            subdomain_json.update({"exploit_count":exploits_found})

            subdomain_data.append(subdomain_json)

    API1_json.update({"subdomain_data" : subdomain_data})
    insert_domain(API1_json)
    return API1_json

def getSubdomainInfo(subdomain_name):
    subdomain_json = {}
    jslinks = get_jslinks(subdomain_name)
    # print(jslinks)
    openports = get_openports(subdomain_name)
    pprint(openports)
    vulns_found = get_vulns_found(subdomain_name)
    # pprint(vulns_found)
    
    ip = get_ip(subdomain_name)

    tech_found = get_tech_found(subdomain_name)
    # print(tech_found)
    security_posture = get_security_posture(vulns_found)
    # updating the subdomain json

    if security_posture >= 75:
        status = "high risk"
    elif security_posture >= 50:
        status = "medium risk"
    elif security_posture >=25:
        status = "low risk"
    elif security_posture > 0:
        status = "very low risk"
    else:
        status = "safe"
    
    subdomain_json.update({"ip":ip})
    subdomain_json.update({"subdomain_name":subdomain_name})
    subdomain_json.update({"js_links":jslinks})
    subdomain_json.update({"open_ports": openports})
    subdomain_json.update({"vulnerability_data":vulns_found})
    subdomain_json.update({"tech_found":tech_found})
    subdomain_json.update({"status": status})
    subdomain_json.update({"security_posture": security_posture})
    insert_subdomain(subdomain_json)
    return subdomain_json


def connect_db(xyz):
    try:
        client = pymongo.MongoClient("<changethis>")
        db = client.cloudRTF
        return db[xyz]
    except Exception as error:
        print("Error while connecting to db: ", error)
        
def insert_domain(data):
    try:
        xyz = 'domaininfo'
        metadb = connect_db(xyz)
        metadb.insert_one(data)
        return True
    except Exception as err:
        print("Error while inserting records: ", err)

def insert_subdomain(data):
    pass
    try:
        xyz = 'subdomaininfo'
        metadb = connect_db(xyz)
        metadb.insert_one(data)
        return True
    except Exception as err:
        print("Error while inserting records: ", err)


def subdomain():
    with open(f"Subdomains/{domain_name}_subdomain_results.txt") as f:
        subdomain_list = f.read()
    subdomain_names = subdomain_list.split("\n")
    for subdomain_name in subdomain_names:
        if subdomain_name:
            subdomain_info = getSubdomainInfo(subdomain_name)
    

# if __name__ == "__main__":
#     domain_name = input("Enter domain:\n")
#     getDomainInfo(domain_name)
#     subdomain()
    
    
        

    
    



