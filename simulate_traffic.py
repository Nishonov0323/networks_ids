# simulate_traffic.py
from scapy.all import IP, TCP, send
import requests
import time


# Simulate a DoS attack by sending many packets from the same source IP
def simulate_dos_attack():
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.200"
    dst_port = 80

    # Create a packet
    packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, sport=12345)

    # Send 200 packets to trigger the "High Packet Rate (DoS)" rule
    for i in range(200):
        packet[TCP].sport = 12345 + i  # Vary the source port slightly
        raw_packet = bytes(packet)
        # Send packet to the ingest endpoint
        response = requests.post(
            "http://127.0.0.1:8000/api/ingest/",
            json={'raw_packet': raw_packet.hex()}  # Convert to hex for JSON serialization
        )
        print(f"Packet {i + 1}: {response.json()}")
        time.sleep(0.01)  # Small delay to simulate real traffic


# Simulate a port scan by sending packets to multiple ports
def simulate_port_scan():
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.200"

    # Send packets to 15 different ports to trigger the "Port Scan Detection" rule
    for port in range(80, 95):  # Ports 80 to 94
        packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=port, sport=12345)
        raw_packet = bytes(packet)
        response = requests.post(
            "http://127.0.0.1:8000/api/ingest/",
            json={'raw_packet': raw_packet.hex()}
        )
        print(f"Port {port}: {response.json()}")
        time.sleep(0.01)


if __name__ == "__main__":
    print("Simulating DoS attack...")
    simulate_dos_attack()
    print("\nSimulating port scan...")
    simulate_port_scan()
