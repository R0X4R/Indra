import argparse
import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import xml.etree.ElementTree as ET
import socket
from datetime import datetime
import time
from Wappalyzer import Wappalyzer, WebPage
import warnings
import os
import sys
import contextlib
import re
import ipaddress

warnings.filterwarnings("ignore")

# console = Console()
max_threads = 500

@contextlib.contextmanager
def suppress_stdout_stderr():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = devnull
        sys.stderr = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

def fetch_open_ports(domain):
    try:
        url = f"https://internetdb.shodan.io/{domain}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get('ports', []), data.get('vulns', [])
        else:
            return [], []
    except Exception as e:
        return [], []

def fallback_scan(domain, port_range):
    open_ports = []

    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((domain, port))
        sock.close()
        if result == 0:
            return port
        return None

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_port, port): port for port in port_range}
        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)

    return open_ports

def find_version(a):
    if a == []:
        return 'nil'
    else:
        return a[0]

def check_technologies(domain, port):
    url = f"http://{domain}:{port}"
    try:
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        techs = wappalyzer.analyze_with_versions_and_categories(webpage)

        technologies = []
        categories_to_show = ['databases', 'web-servers', 'cdn', 'cms']
        for tech, details in techs.items():
            version = find_version(details['versions'])
            category = details['categories'][0].lower()
            if category in categories_to_show:
                tech_info = f"{tech}"
                if version != 'nil':
                    tech_info += f" v{version}"
                technologies.append(tech_info)

        return technologies
    except:
        return ["Technology detection failed"]

def verify_with_nmap(domain, ports, output_format):
    command = [
        "nmap", "-p", ",".join(map(str, ports)), domain,
        "-sV", "-T4", "--min-rate=1000", "-oX", "-"
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output, error = process.communicate()
    except KeyboardInterrupt:
        print("\nStopping the scan...")
        return None

    if output:
        xml_output = output.decode()
        results = parse_nmap_xml(xml_output)

        # Check technologies for each open port
        for result in results:
            if result['state'] == 'open':
                with suppress_stdout_stderr():
                    technologies = check_technologies(domain, result['port'])
                result['technologies'] = technologies

        if output_format == "json":
            json_output = convert_nmap_to_json(xml_output, results)
            return json_output
        elif output_format == "xml":
            return xml_output
        elif output_format == "port_only":
            return generate_port_only_output(domain, results)
        else:
            formatted_output = generate_scan_output(domain, results)
            return formatted_output

    if error:
        return None

def parse_nmap_xml(xml_output):
    root = ET.fromstring(xml_output)
    results = []

    for port in root.findall(".//port"):
        port_data = {
            "port": port.get("portid"),
            "protocol": port.get("protocol", "tcp"),
            "state": port.find("./state").get("state"),
            "service": port.find("./service").get("name"),
            "version": port.find("./service").get("version", "unknown")
        }
        results.append(port_data)

    return results

def generate_scan_output(domain, results):
    open_ports = ", ".join(str(result['port']) for result in results if result['state'] == 'open')
    output = f"\nPorts found: {open_ports}\n\n"
    output += "PORT      STATE  SERVICE      VERSION      TECHNOLOGIES\n"

    sorted_results = sorted(results, key=lambda x: int(x['port']))

    for result in sorted_results:
        port_str = f"{result['port']}/{result['protocol']}"
        technologies = ", ".join(result.get('technologies', ["unknown"]))
        technologies = re.sub(r' \[version: nil\]', '', technologies)
        technologies = re.sub(r' \[version:(\S+)\]', r' v\1', technologies)
        output += f"{port_str:<9} {result['state']:<6} {result['service']:<12} {result['version']:<12} {technologies}\n"

    return output

def generate_port_only_output(domain, results):
    output = ""
    for result in results:
        if result['state'] == 'open':
            output += f"{domain}:{result['port']}\n"
    return output

def convert_nmap_to_json(xml_output, results):
    root = ET.fromstring(xml_output)
    scan_data = {"host": {}, "ports": []}

    for elem in root.findall(".//host"):
        scan_data["host"]["status"] = elem.find("./status").get("state")

    for elem in root.findall(".//address"):
        scan_data["host"]["address"] = elem.get("addr")

    for result in results:
        port_data = {
            "port": result['port'],
            "state": result['state'],
            "service": result['service'],
            "version": result['version'],
            "technologies": result.get('technologies', ["unknown"])
        }
        scan_data["ports"].append(port_data)

    return json.dumps(scan_data, indent=4)

def run_scan(target, ports=None, output_format="text", scan_range=None):
    start_time = time.time()
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
    scan_info = {
        "start_time": current_time,
        "target": target,
        "host_status": "unknown"
    }

    # Print initial information immediately
    if output_format != "port_only":
        print(f"\nStarting Indraa ( https://github.com/R0X4R/Indraa ) at {current_time}")
        print(f"indraa scan report for {target}")

    # Check host status
    try:
        subprocess.check_call(["ping", "-c", "1", target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        scan_info["host_status"] = "up"
    except subprocess.CalledProcessError:
        scan_info["host_status"] = "down"

    if output_format != "port_only":
        print(f"Host is {scan_info['host_status']}")

    fallback_message = "NOTE: We found no data from InternetDB, used fallback Python scanning."
    used_fallback = False

    if ports:
        port_list = ports
        vulnerabilities = []
    else:
        port_list, vulnerabilities = fetch_open_ports(target)
        if not port_list:
            port_list = fallback_scan(target, scan_range)
            used_fallback = True

    scan_result = None
    if port_list:
        try:
            scan_result = verify_with_nmap(target, port_list, output_format)
        except KeyboardInterrupt:
            if output_format != "port_only":
                print("\nStopping the scan...")
            return
    else:
        scan_info["ports"] = []

    if used_fallback:
        scan_info["fallback_used"] = True

    end_time = time.time()
    scan_duration = end_time - start_time
    scan_info["duration"] = f"{scan_duration:.2f}"

    if output_format == "json":
        if scan_result:
            full_result = json.loads(scan_result)
            full_result.update(scan_info)
        else:
            full_result = scan_info
        if vulnerabilities:
            full_result["vulnerabilities"] = vulnerabilities
        print(json.dumps(full_result, indent=4))
    elif output_format == "port_only":
        if scan_result:
            print(scan_result, end='')
    else:
        if scan_result:
            print(scan_result)
        else:
            print("No open ports found")
        if vulnerabilities:
            print("\nVulnerabilities:")
            for vuln in vulnerabilities:
                print(f"- {vuln}")
        if used_fallback:
            print(fallback_message)
        print(f"Scan completed in {scan_duration:.2f} seconds")

def parse_args():
    parser = argparse.ArgumentParser(description="Indraa is a powerful, versatile, and user-friendly Python-based network scanning and vulnerability assessment tool.", add_help=False)
    parser.add_argument("target", nargs="?", help="The target domain, IP address, or CIDR range to scan")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g. 22,80,443 or 21-30)", type=str)
    parser.add_argument("-oX", "--output-xml", help="Output scan in XML format", action="store_true")
    parser.add_argument("-oJ", "--output-json", help="Output scan in JSON format", action="store_true")
    parser.add_argument("-oN", "--output-normal", help="Output scan in normal text format", action="store_true")
    parser.add_argument("-oP", "--output-port-only", help="Output only IP and port in format ip:port", action="store_true")
    parser.add_argument("-iL", "--input-list", help="Input from list of hosts/networks", type=str)
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    return parser.parse_args()

def usage():
    print("""
Indraa is a powerful, versatile, and user-friendly Python-based network scanning and vulnerability assessment tool.

USAGE:

    indraa [flags]

POSITIONAL ARGUMENTS:

    target                The target domain, IP address, or CIDR range to scan

FLAGS:
    -p, --ports             string    Ports to scan (e.g. 22,80,443 or 21-30)
    -oX, --output-xml                 Output scan in XML format
    -oJ, --output-json                Output scan in JSON format
    -oN, --output-normal              Output scan in normal text format
    -oP, --output-port-only           Output only IP and port in format ip:port
    -iL, --input-list       string    Input from list of hosts/networks
    -h, --help                        Show this help message and exit
    """)

def expand_cidr(cidr):
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(cidr)]
    except ValueError:
        print(f"Invalid CIDR notation: {cidr}")
        return []

def parse_port_range(port_arg):
    if '-' in port_arg:
        start, end = map(int, port_arg.split('-'))
        return list(range(start, end + 1))
    else:
        return list(map(int, port_arg.split(",")))

if __name__ == "__main__":
    args = parse_args()

    if args.help:
        usage()
        sys.exit(0)

    if args.input_list:
        with open(args.input_list, 'r') as f:
            targets = f.read().splitlines()
    elif args.target:
        if '/' in args.target:  # CIDR notation
            targets = expand_cidr(args.target)
        else:
            targets = [args.target]
    elif not sys.stdin.isatty():
        targets = sys.stdin.read().splitlines()
    else:
        print("Error: No target specified. Please provide a target or use -iL for input from a file.")
        sys.exit(1)

    if args.ports:
        ports = parse_port_range(args.ports)
    else:
        ports = None

    if args.output_xml:
        output_format = "xml"
    elif args.output_json:
        output_format = "json"
    elif args.output_port_only:
        output_format = "port_only"
    else:
        output_format = "text"

    default_ports = [
        21, 22, 80, 81, 280, 300, 443, 583, 591, 593, 832, 981, 1010, 1099, 1311,
        2082, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4444, 4445, 4567,
        4711, 4712, 4993, 5000, 5104, 5108, 5280, 5281, 5601, 5800, 6543, 7000,
        7001, 7002, 7396, 7474, 8000, 8001, 8008, 8009, 8014, 8042, 8060, 8069,
        8080, 8081, 8083, 8088, 8090, 8091, 8095, 8118, 8123, 8172, 8181, 8222,
        8243, 8280, 8281, 8333, 8337, 8443, 8500, 8530, 8531, 8834, 8880, 8887,
        8888, 8983, 9000, 9001, 9043, 9060, 9080, 9090, 9091, 9092, 9200, 9443,
        9502, 9800, 9981, 10000, 10250, 10443, 11371, 12043, 12046, 12443, 15672,
        16080, 17778, 18091, 18092, 20720, 28017, 32000, 55440, 55672
    ]

    try:
        for target in targets:
            run_scan(target, ports=ports, output_format=output_format, scan_range=default_ports)
    except KeyboardInterrupt:
        if output_format != "port_only":
            exit()
