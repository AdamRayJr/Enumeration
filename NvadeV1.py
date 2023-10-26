#########################################
# Author: Adam Ray Jr
# Date: 2023-10-19
# Tested with Python v3/Nmap v7.94
# Github: https://github.com/AdamRayJr/
#########################################


import os
import subprocess
import re
import ipaddress
import readline
from datetime import datetime

try:
    from termcolor import colored
except ImportError:
    print("Consider installing 'termcolor' for colored ASCII art.")
    colored = lambda x, y: x

ASCII_ART = """
+--------------------------------------------+
|                                            |
|    _   __                __             ___|
|   / | / /   ______ _____/ /__     _   _<  /|
|  /  |/ / | / / __ `/ __  / _ \   | | / / / |
| / /|  /| |/ / /_/ / /_/ /  __/   | |/ / /  |
|/_/ |_/ |___/\__,_/\__,_/\___/    |___/_/   |
|                                            |
+--------------------------------------------+
"""

print(colored(ASCII_ART, 'cyan'))



NMAP_SIMPLE_COMMAND = ["nmap", "-p-", "-Pn", "--stats-every", "10s"]
NMAP_DETAILED_COMMAND = ["sudo", "nmap", "-sS", "-sC", "-sV", "-O", "-Pn", "--stats-every", "10s"]
# List of evasion techniques with nmap commands
EVADE_TECHNIQUES = [
    ["sudo", "nmap", "-sS", "-T2", "-f", "-Pn", "--stats-every", "10s"],   # Fragment packets
    ["sudo", "nmap", "-sS", "-T2", "--mtu", "24", "-Pn", "--stats-every", "10s"],  # Specify custom MTU size
    ["sudo", "nmap", "-sS", "-T2", "--scan-delay", "500ms", "-Pn", "--stats-every", "10s"]  # Introduce delay
    # ... add more techniques as needed ...
]

def run_command(command):
    output = []
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, bufsize=1)
    while True:
        line = process.stdout.readline()
        if not line and process.poll() is not None:
            break
        if line:
            output.append(line)
            print(line.strip())
    _, _ = process.communicate()  # To ensure process completes and any remaining output is captured
    return ''.join(output)

def simple_nmap_scan(target, exclude_ips=None):
    command = NMAP_SIMPLE_COMMAND.copy()
    if exclude_ips:
        command.extend(["--exclude", exclude_ips])
    command.append(target)
    return run_command(command)

def extract_open_ports(nmap_output):
    open_ports = []
    # Simple regex to match multiple spaces/tabs between port number and the state
    matches = re.findall(r"(\d+)/tcp\s+open", nmap_output)
    for match in matches:
        open_ports.append(match)
    return ",".join(open_ports)

def detailed_nmap_scan(ports, target, filename, exclude_ips=None):
    command = NMAP_DETAILED_COMMAND.copy() + [f"-p{ports}", target]
    if exclude_ips:
        command += ["--exclude", exclude_ips]
    command += ["-oX", filename]
    return run_command(command)

def get_target():
    readline.set_completer_delims(' \t\n')
    readline.parse_and_bind("tab: complete")

    while True:
        option = input("Do you want to enter the target manually or use a file? (manual/file) [default=manual]: ").lower()

        if not option or option == "manual":
            while True:
                target = input("Enter the target IP / IP range / domain to scan: ")
                if is_valid_ip(target) or is_valid_cidr(target) or is_valid_domain(target):
                    return target
                else:
                    print("Invalid input. Please enter a valid IP, IP range, or domain.")
        elif option == "file":
            file_path = input("Enter the path to the file with the list of IPs: ")
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    return ",".join(f.read().splitlines())
            else:
                print("File not found. Please check the path and try again.")
        else:
            print("Invalid choice. Please choose 'manual' or 'file', or press Enter for default.")

def get_exclude_ips():
    while True:  # Continue prompting until valid input is received
        readline.set_completer_delims(' \t\n')
        readline.parse_and_bind("tab: complete")

        option = input("Do you want to exclude certain IPs? (yes/no) [default=no]: ").lower()

        if not option or option == "no":
            return None
        elif option == "yes":
            exclude_method = input("Do you want to enter the IPs to exclude manually or use a file? (manual/file) [default=manual]: ").lower()

            if not exclude_method or exclude_method == "manual":
                return input("Enter the IPs to exclude, separated by commas (e.g. 192.168.x.1,192.168.x.2): ")
            elif exclude_method == "file":
                file_path = input("Enter the path to the file with the list of IPs to exclude: ")
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        return ",".join(f.read().splitlines())
                else:
                    print("File not found. Please check the path and try again.")
            else:
                print("Invalid choice. Please choose 'manual' or 'file', or press Enter for default.")
        else:
            print("Invalid input. Please type 'yes' or 'no', or press Enter for default.")

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_valid_cidr(cidr_str):
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    # Regex pattern for a basic domain validation
    pattern = r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$'
    return re.match(pattern, domain, re.IGNORECASE) is not None
    
def run_evade_techniques(target, exclude_ips=None):
    for technique in EVADE_TECHNIQUES:
        command = technique + [target]
        if exclude_ips:
            command += ["--exclude", exclude_ips]
        
        print(f"\nRunning Nmap with evasion technique: {' '.join(technique[2:])} on {target}...\n")
        evasion_output = run_command(command)
        
        open_ports = extract_open_ports(evasion_output)
        if open_ports:
            print(f"\nExtracted open ports using evasion technique: {open_ports}")
            return open_ports
    return None  # Return None if no open ports found after all evasion techniques

def main():
    target = get_target()
    exclude_ips = None if is_valid_ip(target) or is_valid_cidr(target) or is_valid_domain(target) else get_exclude_ips()

    while True:
        simple_filename = input("Enter the desired output filename (e.g. clientname): ").strip()
        if simple_filename:  # If the filename is not an empty string
            break
        print("Filename cannot be empty. Please enter a valid filename.")

    current_datetime = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{simple_filename}_nmap_results_{current_datetime}.xml"

    print(f"\nRunning simple Nmap scan (nmap -p- -Pn) on {target}...\n")
    simple_nmap_output = simple_nmap_scan(target, exclude_ips)

    open_ports = extract_open_ports(simple_nmap_output)
    
    if open_ports:
        print(f"\nExtracted open ports: {open_ports}")
        print(f"\nRunning detailed Nmap scan (sudo nmap -sS -sC -sV -O -Pn) on {target} for the detected open ports...")
        detailed_nmap_scan(open_ports, target, filename, exclude_ips)
        print(f"\nScan complete. Results saved to {filename}")
    else:
        print("\nNo open ports found in the initial scan. Applying evasion techniques...")
        evasion_ports = run_evade_techniques(target, exclude_ips)
        
        if evasion_ports:
            print(f"\nRunning detailed Nmap scan (sudo nmap -sS -sC -sV -O -Pn) on {target} for the detected open ports after evasion...")
            detailed_nmap_scan(evasion_ports, target, filename, exclude_ips)
            print(f"\nScan complete. Results saved to {filename}")
        else:
            print("\nNo open ports found even after applying all evasion techniques.")

if __name__ == "__main__":
    main()
