
import time
import socket
import json
import dns.resolver
import requests
import re
import subprocess
from collections import defaultdict
import maxminddb  

def scan_websites(domains):
    results = defaultdict(dict)

    for domain in domains:
        # Get the current time in UNIX epoch seconds
        scan_time = time.time()
        results[domain]['scan_time'] = scan_time

        # Scan for IPv4 addresses
        try:
            ipv4_addresses = socket.gethostbyname_ex(domain)[2]
        except socket.gaierror:
            ipv4_addresses = []
        results[domain]['ipv4_addresses'] = ipv4_addresses

        # Scan for IPv6 addresses
        try:
            ipv6_addresses = dns.resolver.resolve(domain, 'AAAA')
            ipv6_addresses = [str(address) for address in ipv6_addresses]
        except dns.resolver.NoAnswer:
            ipv6_addresses = []
        results[domain]['ipv6_addresses'] = ipv6_addresses

        # Scan for the HTTP server
        try:
            response = requests.head(f"http://{domain}", timeout=5)
            http_server = response.headers.get("Server", '')
        except requests.RequestException:
            http_server = ''
        results[domain]['http_server'] = http_server

    # Convert the results dictionary into a JSON object
    json_object = json.dumps(results, sort_keys=True, indent=4)

    return json_object

def run_command(command, timeout=2):
    try:
        result = subprocess.check_output(command, timeout=timeout, stderr=subprocess.STDOUT).decode("utf-8")
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("Command execution timed out.", file=sys.stderr)

def get_ipv4_addresses(domain):
    command = ["nslookup", domain]
    result = run_command(command)
    ipv4_addresses = re.findall(r'Address: ([\d.]+)', result)
    return ipv4_addresses

def get_ipv6_addresses(domain):
    command = ["nslookup", "-type=AAAA", domain]
    result = run_command(command)
    ipv6_addresses = re.findall(r'Address: ([\da-fA-F:]+)', result)
    return ipv6_addresses

def get_http_server(domain):
    try:
        response = requests.head(f"http://{domain}", timeout=5)
        http_server = response.headers.get("Server", None)
        return http_server
    except requests.RequestException:
        return None

def scan_insecure_http(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        return response.url.startswith("http://")
    except requests.RequestException:
        return None

def scan_redirect_to_https(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=False)
        if response.status_code in [301, 302, 303, 307, 308]:
            return response.headers.get("Location", "").startswith("https://")
        return False
    except requests.RequestException:
        return None

def scan_hsts(domain):
    try:
        response = requests.head(f"https://{domain}", timeout=5)
        return 'strict-transport-security' in response.headers
    except requests.RequestException:
        return False

def scan_tls_versions(domain):
    try:
        command = ["openssl", "s_client", "-tls1_3", "-connect", f"{domain}:443"]
        result = run_command(command)
        versions = re.findall(r"Protocol[ ]*:[ ]*(\w+)", result)
        return versions
    except subprocess.CalledProcessError:
        return None

def scan_root_ca(domain):
    try:
        command = ["openssl", "s_client", "-connect", f"{domain}:443"]
        result = run_command(command)
        root_ca = re.search(r"O[ ]*=[ ]*([^,]+)", result)
        return root_ca.group(1) if root_ca else None
    except subprocess.CalledProcessError:
        return None

def scan_rdns_names(ipv4_addresses):
    rdns_names = []
    for ip in ipv4_addresses:
        try:
            result = socket.gethostbyaddr(ip)
            rdns_names.append(result[0])
        except socket.herror:
            rdns_names.append(None)
    return rdns_names

def scan_rtt_range(ipv4_addresses):
    rtt_values = []
    for ip in ipv4_addresses:
        try:
            command = ["sh", "-c", f"time echo -e '\x1dclose\x0d' | telnet {ip} 443"]
            result = run_command(command)
            rtt = re.search(r"real[ ]*(\d+)[ ]*m(\d+\.\d+)", result)
            if rtt:
                rtt_values.append(float(rtt.group(1)) * 60 + float(rtt.group(2)))
        except subprocess.CalledProcessError:
            pass
    if not rtt_values:
        return None
    return [min(rtt_values), max(rtt_values)]

def scan_geo_locations(ipv4_addresses):
    geo_locations = set()
    reader = maxminddb.open_database('GeoLite2-City.mmdb')
    for ip in ipv4_addresses:
        try:
            response = reader.get(ip)
            if response and 'city' in response and 'subdivisions' in response and 'country' in response:
                city = response['city']['names']['en']
                subdivision = response['subdivisions'][0]['names']['en']
                country = response['country']['names']['en']
                geo_locations.add(f"{city}, {subdivision}, {country}")
        except (maxminddb.errors.InvalidDatabaseError, KeyError):
            pass
    reader.close()
    return list(geo_locations)

if __name__ == "__main__":
    import sys

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Read the list of web domains from the input file
    with open(input_file, "r") as f:
        domains = [line.strip() for line in f]

    # Initialize the results dictionary
    results = defaultdict(dict)

    # Iterate over domains and perform scans
    for domain in domains:
        results[domain]['scan_time'] = time.time()
        results[domain]['ipv4_addresses'] = get_ipv4_addresses(domain)
        results[domain]['ipv6_addresses'] = get_ipv6_addresses(domain)
        results[domain]['http_server'] = get_http_server(domain)
        results[domain]['insecure_http'] = scan_insecure_http(domain)
        results[domain]['redirect_to_https'] = scan_redirect_to_https(domain)
        results[domain]['hsts'] = scan_hsts(domain)
        results[domain]['tls_versions'] = scan_tls_versions(domain)
        results[domain]['root_ca'] = scan_root_ca(domain)

        # Scan rdns_names, rtt_range, and geo_locations only if IPv4 addresses are available
        if results[domain]['ipv4_addresses']:
            results[domain]['rdns_names'] = scan_rdns_names(results[domain]['ipv4_addresses'])
            results[domain]['rtt_range'] = scan_rtt_range(results[domain]['ipv4_addresses'])
            results[domain]['geo_locations'] = scan_geo_locations(results[domain]['ipv4_addresses'])

    # Convert the results dictionary into a JSON object
    json_object = json.dumps(results, sort_keys=True, indent=4)

    # Write the JSON object to the output file
    with open(output_file, "w") as f:
        f.write(json_object)
