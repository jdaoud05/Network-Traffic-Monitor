import os
import sys
import time
import subprocess
from collections import defaultdict
from scapy.all import sniff, IP, TCP

PACKET_THRESHOLD = 40
print(f"PACKET_THRESHOLD: {PACKET_THRESHOLD}")

# Read IP addresses from a file
def load_ip_file(file_path):
    with open(file_path, "r") as file:
        ip_addresses = [line.strip() for line in file]
    return set(ip_addresses)

# Check for Nimda worm signature in a packet
def detect_nimda_signature(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload_data = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload_data)
    return False

# Log events to a file
def record_event(log_message):
    logs_directory = "logs"
    os.makedirs(logs_directory, exist_ok=True)
    log_file_name = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file_path = os.path.join(logs_directory, f"log_{log_file_name}.txt")
    
    with open(log_file_path, "a") as log_file:
        log_file.write(f"{log_message}\n")

# Block an IP using Windows netsh command
def block_ip(ip_address):
    command = f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}'
    try:
        subprocess.run(command, shell=True, check=True)
        record_event(f"Blocked IP: {ip_address}")
    except subprocess.CalledProcessError as error:
        record_event(f"Failed to block IP {ip_address}: {error}")

def handle_packet(packet):
    source_ip = packet[IP].src

    # Skip if the IP is in the whitelist
    if source_ip in allowed_ips:
        return

    # Block immediately if the IP is in the blacklist
    if source_ip in denied_ips:
        block_ip(source_ip)
        record_event(f"Blocked blacklisted IP: {source_ip}")
        return
    
    # Detect Nimda worm signature
    if detect_nimda_signature(packet):
        print(f"Blocking Nimda source IP: {source_ip}")
        block_ip(source_ip)
        record_event(f"Blocked Nimda source IP: {source_ip}")
        return

    traffic_count[source_ip] += 1

    current_timestamp = time.time()
    time_elapsed = current_timestamp - start_timestamp[0]

    if time_elapsed >= 1:
        for ip, count in traffic_count.items():
            packet_rate = count / time_elapsed

            if packet_rate > PACKET_THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                block_ip(ip)
                record_event(f"Blocked IP: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)

        traffic_count.clear()
        start_timestamp[0] = current_timestamp

if __name__ == "__main__":
    # Load whitelist and blacklist
    allowed_ips = load_ip_file("whitelist.txt")
    denied_ips = load_ip_file("blacklist.txt")

    traffic_count = defaultdict(int)
    start_timestamp = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=handle_packet)
