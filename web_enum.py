import os
import sys
import requests
import socket
import requests
import subprocess
import dns.resolver
import urllib.request
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def make_output_dir(domain):
    safe_domain = domain.replace("http://", "").replace("https://", "").replace("/", "_")
    dir_name = f"output_{safe_domain}"
    os.makedirs(dir_name, exist_ok=True)
    return dir_name

def save_to_file(directory, domain, info_type, data):
    file_path = os.path.join(directory, f"{domain}_{info_type}.txt")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(data)

def check_live(domain):
    print("[*] Checking if site is live...")
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        return f"[+] {domain} is live. Status Code: {res.status_code}"
    except requests.RequestException as e:
        return f"[-] {domain} is not reachable.\n{e}"

def get_ip(domain):
    print("[*] Getting IP address...")
    try:
        ip = socket.gethostbyname(domain)
        return f"{domain} resolves to {ip}"
    except socket.gaierror as e:
        return f"Error resolving {domain}: {e}"










def get_whois_data(ip_address):
    """
    Runs the 'whois' command on the given IP address and returns the output.
    """
    try:
        result = subprocess.run(["whois", ip_address], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running whois: {e}")
        return None
    except FileNotFoundError:
        print("[-] 'whois' command not found. Please install it.")
        return None













def get_dns_records(domain):
    print("[*] Getting DNS records...")
    result = []
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            result.append(f"{record} Records:")
            result.extend(str(rdata) for rdata in answers)
        except Exception:
            result.append(f"{record} lookup failed.")
    return "\n".join(result)

def get_headers(domain):
    print("[*] Getting HTTP headers...")
    try:
        res = requests.get(f"http://{domain}", timeout=5)
        headers = res.headers
        return "\n".join([f"{k}: {v}" for k, v in headers.items()])
    except Exception as e:
        return f"Header fetch failed: {e}"

def get_robots(domain):
    print("[*] Fetching robots.txt...")
    try:
        res = requests.get(f"http://{domain}/robots.txt", timeout=5)
        return res.text if res.status_code == 200 else "robots.txt not found"
    except Exception as e:
        return f"robots.txt fetch failed: {e}"

def download_subdomain_wordlist(wordlist_path):
    print("[*] Downloading subdomain wordlist...")
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/namelist.txt"
    try:
        urllib.request.urlretrieve(url, wordlist_path)
        print("[+] Wordlist downloaded.")
    except Exception as e:
        print(f"[!] Failed to download wordlist: {e}")

def resolve_subdomain(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return f"[+] Found: {subdomain} -> {ip}"
    except socket.gaierror:
        return None

def enumerate_subdomains(domain):
    print("[*] Enumerating subdomains...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    wordlist_path = os.path.join(script_dir, "subdomains.txt")

    if not os.path.exists(wordlist_path):
        download_subdomain_wordlist(wordlist_path)

    found = []
    try:
        with open(wordlist_path, "r") as f:
            subdomains = [f"{line.strip()}.{domain}" for line in f if line.strip()]

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(resolve_subdomain, sub): sub for sub in subdomains}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    print(result)
                    found.append(result)

    except Exception as e:
        found.append(f"Subdomain enumeration failed: {str(e)}")

    return "\n".join(found)

def port_scan(domain):
    print("[*] Performing port scan with nmap...")
    try:
        result = subprocess.check_output(["nmap", "-T4", "-F", domain], stderr=subprocess.STDOUT)
        return result.decode()
    except subprocess.CalledProcessError as e:
        return f"[-] Nmap scan failed:\n{e.output.decode()}"

def run_enumeration(target_domain):
    parsed_domain = urlparse(target_domain).netloc or target_domain
    parsed_domain = parsed_domain.strip().lower()
    out_dir = make_output_dir(parsed_domain)

    print(f"\n[*] Starting enumeration on: {parsed_domain}\n")

    live_status = check_live(parsed_domain)
    save_to_file(out_dir, parsed_domain, "live_status", live_status)

    ip_info = get_ip(parsed_domain)
    save_to_file(out_dir, parsed_domain, "ip", ip_info)
    
    
    
    
    
    
    
    #Whois
    #ip_address = get_ip(parsed_domain)
    #whois_result = run_whois(ip_address)
    #save_to_file(out_dir, parsed_domain, "whois_domain", whois_result)
    
    
    #run_whois(parsed_domain)
    
    
    # --- Your domain input ---
    try:
    	ip_address = socket.gethostbyname(parsed_domain)
    	print(f"[+] Resolved {parsed_domain} to IP: {ip_address}")
    except socket.gaierror:
    	print(f"[-] Could not resolve domain: {parsed_domain}")
    	ip_address = None
    
    if ip_address:
    	whois_output = get_whois_data(ip_address)
    	
    	if whois_output:
    		output_dir = "output_domain"
    		
    		file_name = f"{parsed_domain}_whois.txt"
    		file_path = os.path.join(out_dir, file_name)
    		
    		with open(file_path, "w", encoding="utf-8") as f:
    			f.write(whois_output)
    		print(f"[+] WHOIS data for {parsed_domain} saved to: {file_path}")

    
   


    dns_info = get_dns_records(parsed_domain)
    save_to_file(out_dir, parsed_domain, "dns", dns_info)

    headers_info = get_headers(parsed_domain)
    save_to_file(out_dir, parsed_domain, "headers", headers_info)

    robots_info = get_robots(parsed_domain)
    save_to_file(out_dir, parsed_domain, "robots", robots_info)

    subdomain_info = enumerate_subdomains(parsed_domain)
    save_to_file(out_dir, parsed_domain, "subdomains", subdomain_info)

    portscan_info = port_scan(parsed_domain)
    save_to_file(out_dir, parsed_domain, "portscan", portscan_info)

    print(f"\n[✔] All results saved in: {out_dir}")

if __name__ == "__main__":
    target = input("Enter target domain (e.g. example.com): ").strip()
    run_enumeration(target)
