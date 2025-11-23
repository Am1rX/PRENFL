#!/usr/bin/env python3
import subprocess
import os
import sys
import platform
import re
import time
import signal
import shutil

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RED_BOLD = '\033[1;31m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    WHITE = '\033[97m'

IS_DEBIAN = os.path.exists('/var/log/syslog')
LOG_AUTH = '/var/log/auth.log' if IS_DEBIAN else '/var/log/secure'
LOG_SYS = '/var/log/syslog' if IS_DEBIAN else '/var/log/messages'

def run_cmd(command, shell=False):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result.decode('utf-8').strip()
    except subprocess.CalledProcessError:
        return None

def check_root():
    if os.geteuid() != 0:
        print(f"{Colors.FAIL}[ERROR] Root access required! Please run with sudo.{Colors.ENDC}")
        sys.exit(1)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_resource_usage():
    try:
        with open('/proc/meminfo', 'r') as f:
            lines = f.readlines()
        mem_total = int(lines[0].split()[1]) // 1024
        mem_free = int(lines[1].split()[1]) // 1024
        mem_used = mem_total - mem_free
        ram_info = f"{mem_used}MB / {mem_total}MB"
    except:
        ram_info = "N/A"

    try:
        total, used, free = shutil.disk_usage("/")
        disk_info = f"{used // (2**30)}GB / {total // (2**30)}GB"
    except:
        disk_info = "N/A"
        
    try:
        load = os.getloadavg()
        load_info = f"{load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}"
    except:
        load_info = "N/A"
        
    return ram_info, disk_info, load_info

def get_server_info():
    hostname = platform.node()
    kernel = platform.release()
    distro = run_cmd("cat /etc/*release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'") or "Linux"
    uptime = run_cmd("uptime -p") or "Unknown"
    ips = run_cmd("hostname -I")
    if not ips: ips = "No IP Found"
    
    ram, disk, load_info = get_resource_usage()

    banner = f"""
{Colors.CYAN}    ____  ____  ________  ___   ______   __    __ 
   / __ \/ __ \/ ____/  |/  /  / ____/  / /   / / 
  / /_/ / /_/ / __/ / /|_/ /  / /_     / /   / /  
 / ____/ _, _/ /___/ /  / /  / __/    / /___/ /___
/_/   /_/ |_/_____/_/  /_/  /_/      /_____/_____/{Colors.ENDC}
    """
    print(banner)
    print(f"{Colors.HEADER}╔{'═'*70}╗{Colors.ENDC}")
    print(f"{Colors.HEADER}║ {Colors.BOLD}{Colors.WHITE}SYSTEM DASHBOARD & SECURITY CENTER{Colors.ENDC}{' '*34}{Colors.HEADER}║{Colors.ENDC}")
    print(f"{Colors.HEADER}╠{'═'*70}╣{Colors.ENDC}")
    print(f"{Colors.HEADER}║ {Colors.BLUE}Hostname :{Colors.ENDC} {hostname:<25} {Colors.BLUE}OS     :{Colors.ENDC} {distro[:20]:<15} {Colors.HEADER}║{Colors.ENDC}")
    print(f"{Colors.HEADER}║ {Colors.BLUE}Kernel   :{Colors.ENDC} {kernel:<25} {Colors.BLUE}Uptime :{Colors.ENDC} {uptime.replace('up ', '')[:20]:<15} {Colors.HEADER}║{Colors.ENDC}")
    print(f"{Colors.HEADER}╠{'─'*70}╣{Colors.ENDC}")
    print(f"{Colors.HEADER}║ {Colors.WARNING}CPU Load :{Colors.ENDC} {load_info:<25} {Colors.WARNING}RAM    :{Colors.ENDC} {ram:<20} {Colors.HEADER}║{Colors.ENDC}")
    print(f"{Colors.HEADER}║ {Colors.WARNING}Disk Use :{Colors.ENDC} {disk:<25} {Colors.WARNING}IPs    :{Colors.ENDC} {ips[:20]:<20} {Colors.HEADER}║{Colors.ENDC}")
    print(f"{Colors.HEADER}╚{'═'*70}╝{Colors.ENDC}")


def colorize_log(line):
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    line = re.sub(ip_pattern, f"{Colors.RED_BOLD}\\1{Colors.ENDC}", line)
    keywords = {
        "Failed password": Colors.FAIL,
        "IPTABLES-BRUTE": Colors.WARNING,
        "IPTABLES-DROP": Colors.FAIL,
        "Invalid user": Colors.FAIL,
        "Accepted": Colors.GREEN,
        "root": Colors.BOLD
    }
    for key, color in keywords.items():
        if key in line:
            line = line.replace(key, f"{color}{key}{Colors.ENDC}")
    return line

def stream_logs(file_path, filter_grep=None):
    print(f"{Colors.HEADER}--- LIVE LOG MONITOR (Ctrl+C to Back) ---{Colors.ENDC}")
    print(f"File: {file_path} | Filter: {filter_grep if filter_grep else 'None'}")
    print("-" * 50)
    cmd = ['tail', '-f', file_path]
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while True:
            line = process.stdout.readline()
            if not line: break
            decoded = line.decode('utf-8', errors='replace').strip()
            if filter_grep and filter_grep not in decoded: continue
            print(colorize_log(decoded))
    except KeyboardInterrupt:
        process.kill()
        return

def soc_menu():
    while True:
        clear_screen()
        print(f"{Colors.FAIL}{Colors.BOLD}   [ SOC DASHBOARD ]   {Colors.ENDC}")
        print("1. Monitor Failed Logins (Auth)")
        print("2. Monitor Firewall Blocks (Brute Force)")
        print("3. Monitor System Log")
        print("b. Back")
        c = input(f"\n{Colors.CYAN}SOC > {Colors.ENDC}").lower()
        if c == '1': stream_logs(LOG_AUTH, "Failed")
        elif c == '2': stream_logs(LOG_SYS, "IPTABLES")
        elif c == '3': stream_logs(LOG_SYS)
        elif c == 'b': break

def detect_services():
    print(f"\n{Colors.BLUE}[🔍] Scanning Services...{Colors.ENDC}")
    output = run_cmd("ss -tulnp")
    services = []
    if output:
        for line in output.split('\n')[1:]:
            parts = line.split()
            if len(parts) < 5: continue
            proto, local = parts[0], parts[4]
            port = local.split(':')[-1] if ':' in local else None
            if port:
                proc = "Unknown"
                if len(parts) > 6 and 'users:' in parts[6]:
                    m = re.search(r'\("([^"]+)"', parts[6])
                    if m: proc = m.group(1)
                if not any(d['port'] == port for d in services):
                    services.append({'port': port, 'proto': proto, 'name': proc})
    return services

def flush_iptables():
    print(f"\n{Colors.WARNING}[!] Flushing Rules...{Colors.ENDC}")
    run_cmd("iptables -F; iptables -X; iptables -t nat -F")
    print(f"{Colors.GREEN}[✔] Cleaned.{Colors.ENDC}")

def setup_base():
    run_cmd("iptables -A INPUT -m conntrack --ctstate INVALID -j LOG --log-prefix 'IPTABLES-INVALID: '")
    run_cmd("iptables -A INPUT -m conntrack --ctstate INVALID -j DROP")
    run_cmd("iptables -A INPUT -i lo -j ACCEPT")
    run_cmd("iptables -A OUTPUT -o lo -j ACCEPT")
    run_cmd("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

def remove_existing_rules(port, proto):

    current_rules = run_cmd("iptables -S INPUT").split('\n')
    deleted = 0
    # الگوی جستجو: دنبال dport و پروتکل میگردیم
    for rule in current_rules:
        if f"dport {port}" in rule and f"-p {proto}" in rule:
            # تبدیل دستور -A (Add) به -D (Delete)
            del_cmd = rule.replace("-A INPUT", "-D INPUT")
            run_cmd(f"iptables {del_cmd}")
            deleted += 1
            
    if deleted > 0:
        print(f"{Colors.WARNING}[!] Removed {deleted} old/conflicting rule(s) for Port {port}/{proto}{Colors.ENDC}")

def add_rule(port, proto, name, anti_brute=False):
    if anti_brute:
        list_name = f"PORT_{port}_LIMIT"
        run_cmd(f"iptables -A INPUT -p {proto} --dport {port} -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name {list_name} -j LOG --log-prefix 'IPTABLES-BRUTE: ' --log-level 4")
        run_cmd(f"iptables -A INPUT -p {proto} --dport {port} -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name {list_name} -j DROP")
        run_cmd(f"iptables -A INPUT -p {proto} --dport {port} -m state --state NEW -m recent --set --name {list_name}")
        run_cmd(f"iptables -A INPUT -p {proto} --dport {port} -j ACCEPT")
        print(f"{Colors.GREEN}✔ Port {port} ({name}) -> {Colors.WARNING}Anti-BF Active{Colors.ENDC}")
    else:
        run_cmd(f"iptables -A INPUT -p {proto} --dport {port} -j ACCEPT")
        print(f"{Colors.GREEN}✔ Port {port} ({name}) -> OPEN{Colors.ENDC}")

def apply_lockdown():
    run_cmd("iptables -A INPUT -j LOG --log-prefix 'IPTABLES-DROP: ' --log-level 4")
    run_cmd("iptables -P INPUT DROP")
    run_cmd("iptables -P FORWARD DROP")
    run_cmd("iptables -P OUTPUT ACCEPT")
    print(f"{Colors.GREEN}[✔] Security Lockdown Applied.{Colors.ENDC}")

def wizard():
    print(f"\n{Colors.HEADER}[ FIREWALL SETUP ]{Colors.ENDC}")
    
    if input(f"{Colors.WARNING}Reset existing rules? (y/n) [y]: {Colors.ENDC}").lower() != 'n':
        flush_iptables()
    else:
        print("Skipping flush...")
    
    setup_base()
    svcs = detect_services()
    
    if svcs:
        print(f"\n{Colors.CYAN}╔══ DETECTED SERVICES ON SYSTEM ══╗{Colors.ENDC}")
        for s in svcs:
            print(f"║ {Colors.BOLD}{s['name']:<20}{Colors.ENDC} : {s['port']}/{s['proto']} ║")
        print(f"{Colors.CYAN}╚═════════════════════════════════╝{Colors.ENDC}")
        
        print(f"\nHow do you want to configure these services?")
        print(f"{Colors.BOLD}[A]{Colors.ENDC}dd ALL automatically (Bulk)")
        print(f"{Colors.BOLD}[M]{Colors.ENDC}anually decide for each one")
        print(f"{Colors.BOLD}[S]{Colors.ENDC}kip detection (Go to custom)")
        
        mode = input(f"\n{Colors.BLUE}Select Mode (a/m/s) [a]: {Colors.ENDC}").lower()
        
        if mode == 'm':
            for s in svcs:
                p, pr, n = s['port'], s['proto'], s['name']
                print(f"\nConfiguring: {Colors.BOLD}{n}{Colors.ENDC} ({p})")
                if input("Allow? (y/n): ").lower() == 'y':
                    remove_existing_rules(p, pr) # پاکسازی احتمالی
                    bf = input(f"   Enable Anti-Brute Force? (y/n): ").lower() == 'y'
                    add_rule(p, pr, n, bf)
                    
        elif mode == 's':
            print("Skipping detected services.")
            
        else: # Default: Auto
            print(f"\n{Colors.BLUE}Configuring ALL detected services...{Colors.ENDC}")
            bf_all = input(f"Enable Anti-Brute Force for ALL applicable services? (y/n) [n]: ").lower() == 'y'
            for s in svcs:
                remove_existing_rules(s['port'], s['proto']) # پاکسازی احتمالی
                add_rule(s['port'], s['proto'], s['name'], bf_all)

    else:
        print(f"{Colors.FAIL}No active services found listening.{Colors.ENDC}")

    while True:
        choice = input(f"\n{Colors.CYAN}Add a custom port manually? (y/n): {Colors.ENDC}").lower()
        if choice != 'y':
            break
            
        c_port = input(f"Enter Port Number: ")
        c_proto = input(f"Enter Protocol (tcp/udp) [default: tcp]: ").lower() or "tcp"
        
        remove_existing_rules(c_port, c_proto)
        
        bf_choice = input(f"Enable {Colors.WARNING}Anti-Brute Force Protection{Colors.ENDC} for port {c_port}? (y/n): ").lower()
        use_bf = True if bf_choice == 'y' else False
        
        add_rule(c_port, c_proto, "Custom", use_bf)
    
    apply_lockdown()

def main():
    check_root()
    while True:
        clear_screen()
        get_server_info()
        print(f"\n{Colors.BOLD}1.{Colors.ENDC} Auto-Secure Server (Wizard)")
        print(f"{Colors.BOLD}2.{Colors.ENDC} View Active Rules")
        print(f"{Colors.BOLD}{Colors.FAIL}3.{Colors.ENDC} SOC DASHBOARD (Live Logs)")
        print(f"{Colors.BOLD}4.{Colors.ENDC} Exit")
        
        c = input(f"\n{Colors.CYAN}Select Option > {Colors.ENDC}")
        if c == '1': wizard(); input("\nDone. Press Enter...")
        elif c == '2': os.system("iptables -L -n -v --line-numbers | head -n 20"); input("\nEnter...")
        elif c == '3': soc_menu()
        elif c == '4': sys.exit()

if __name__ == "__main__":
    main()
