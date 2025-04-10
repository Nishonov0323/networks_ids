# packet_capture.py
import threading
import time
import logging
import json
import requests
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
from django.conf import settings

logger = logging.getLogger(__name__)


class PacketCaptureService:
    """Service for capturing network packets and sending them to the Django IDS"""

    def __init__(self, interface_name, api_url=None):
        """Initialize the packet capture service"""
        self.interface_name = interface_name
        self.api_url = api_url or 'http://localhost:8000/api/ingest/'
        self.is_running = False
        self.capture_thread = None

    def start_capture(self):
        """Start the packet capture process"""
        if self.is_running:
            logger.warning(f"Packet capture already running on {self.interface_name}")
            return False

        self.is_running = True
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

        logger.info(f"Started packet capture on interface {self.interface_name}")
        return True

    def stop_capture(self):
        """Stop the packet capture process"""
        if not self.is_running:
            logger.warning(f"Packet capture not running on {self.interface_name}")
            return False

        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=3.0)

        logger.info(f"Stopped packet capture on interface {self.interface_name}")
        return True

    def _capture_packets(self):
        """Capture packets using scapy and send them to the IDS"""
        try:
            sniff(
                iface=self.interface_name,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda p: not self.is_running
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {str(e)}")
            self.is_running = False

    def _process_packet(self, packet):
        """Process a captured packet and send it to the IDS"""
        try:
            packet_data = {}

            # Extract timestamp
            packet_data['timestamp'] = datetime.now().isoformat()

            # Extract IP header info if present
            if IP in packet:
                packet_data['src_ip'] = packet[IP].src
                packet_data['dst_ip'] = packet[IP].dst
                packet_data['protocol'] = self._get_protocol_name(packet)
                packet_data['size'] = len(packet)

                # Extract TCP/UDP port info if present
                if TCP in packet:
                    packet_data['src_port'] = packet[TCP].sport
                    packet_data['dst_port'] = packet[TCP].dport
                    packet_data['tcp_flags'] = {
                        'syn': 1 if packet[TCP].flags & 0x02 else 0,
                        'ack': 1 if packet[TCP].flags & 0x10 else 0,
                        'fin': 1 if packet[TCP].flags & 0x01 else 0,
                        'rst': 1 if packet[TCP].flags & 0x04 else 0,
                        'psh': 1 if packet[TCP].flags & 0x08 else 0,
                        'urg': 1 if packet[TCP].flags & 0x20 else 0
                    }
                elif UDP in packet:
                    packet_data['src_port'] = packet[UDP].sport
                    packet_data['dst_port'] = packet[UDP].dport
                else:
                    packet_data['src_port'] = 0
                    packet_data['dst_port'] = 0

                # Extract payload (first 100 bytes)
                payload = bytes(packet.payload)
                if len(payload) > 0:
                    packet_data['payload'] = payload[:100].hex()

                # Send packet data to the IDS API
                self._send_to_ids(packet_data)

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def _get_protocol_name(self, packet):
        """Get the protocol name from a packet"""
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        elif ARP in packet:
            return 'ARP'
        else:
            return 'OTHER'

    def _send_to_ids(self, packet_data):
        """Send packet data to the IDS API"""
        try:
            response = requests.post(
                self.api_url,
                json=packet_data,
                headers={'Content-Type': 'application/json'},
                timeout=1.0  # Short timeout to avoid blocking
            )

            if response.status_code != 200:
                logger.warning(f"Failed to send packet to IDS: {response.status_code} - {response.text}")

        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending packet to IDS: {str(e)}")


class InterfaceManager:
    """Manager for network interfaces used for packet capture"""

    def __init__(self, api_url=None):
        """Initialize the interface manager"""
        self.api_url = api_url or 'http://localhost:8000/api/ingest/'
        self.capture_services = {}

    def start_interface(self, interface_name):
        """Start packet capture on an interface"""
        if interface_name in self.capture_services:
            logger.warning(f"Interface {interface_name} already being monitored")
            return False

        capture_service = PacketCaptureService(interface_name, self.api_url)
        if capture_service.start_capture():
            self.capture_services[interface_name] = capture_service
            return True

        return False

    def stop_interface(self, interface_name):
        """Stop packet capture on an interface"""
        if interface_name not in self.capture_services:
            logger.warning(f"Interface {interface_name} not being monitored")
            return False

        capture_service = self.capture_services[interface_name]
        if capture_service.stop_capture():
            del self.capture_services[interface_name]
            return True

        return False

    def get_active_interfaces(self):
        """Get a list of active interfaces"""
        return list(self.capture_services.keys())


# Example usage:
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create interface manager
    manager = InterfaceManager()

    # Start packet capture on eth0
    manager.start_interface('eth0')

    try:
        # Run for a while
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # Stop all interfaces on Ctrl+C
        for interface in manager.get_active_interfaces():
            manager.stop_interface(interface)
        print("Packet capture stopped")