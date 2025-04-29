# ids/management/commands/simulate_traffic.py
from django.core.management.base import BaseCommand
from ids.services import PacketProcessor
import time


class Command(BaseCommand):
    help = 'Simulates network traffic for testing the IDS'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting network traffic simulation...'))
        processor = PacketProcessor()

        # Simulate a packet (same as before)
        packet = {
            'Protocol': 6.0,
            'Flow Duration': 3.0,
            'Total Fwd Packets': 2.0,
            'Total Backward Packets': 0.0,
            'Fwd Packets Length Total': 12.0,
            'Bwd Packets Length Total': 0.0,
            'Fwd Packet Length Max': 6.0,
            'Fwd Packet Length Min': 6.0,
            'Fwd Packet Length Mean': 6.0,
            'Fwd Packet Length Std': 0.0,
            'Bwd Packet Length Max': 0.0,
            'Bwd Packet Length Min': 0.0,
            'Bwd Packet Length Mean': 0.0,
            'Bwd Packet Length Std': 0.0,
            'Flow Bytes/s': 4000000.0,
            'Flow Packets/s': 666666.7,
            'Flow IAT Mean': 3.0,
            'Flow IAT Std': 0.0,
            'Flow IAT Max': 3.0,
            'Flow IAT Min': 3.0,
            'Fwd IAT Total': 3.0,
            'Fwd IAT Mean': 3.0,
            'Fwd IAT Std': 0.0,
            'Fwd IAT Max': 3.0,
            'Fwd IAT Min': 3.0,
            'Bwd IAT Total': 0.0,
            'Bwd IAT Mean': 0.0,
            'Bwd IAT Std': 0.0,
            'Bwd IAT Max': 0.0,
            'Bwd IAT Min': 0.0,
            'Fwd PSH Flags': 0.0,
            'Fwd Header Length': 40.0,
            'Bwd Header Length': 0.0,
            'Fwd Packets/s': 666666.7,
            'Bwd Packets/s': 0.0,
            'Packet Length Min': 6.0,
            'Packet Length Max': 6.0,
            'Packet Length Mean': 6.0,
            'Packet Length Std': 0.0,
            'Packet Length Variance': 0.0,
            'FIN Flag Count': 0.0,
            'SYN Flag Count': 0.0,
            'RST Flag Count': 0.0,
            'PSH Flag Count': 0.0,
            'ACK Flag Count': 1.0,
            'URG Flag Count': 0.0,
            'ECE Flag Count': 0.0,
            'Down/Up Ratio': 0.0,
            'Avg Packet Size': 9.0,
            'Avg Fwd Segment Size': 6.0,
            'Avg Bwd Segment Size': 0.0,
            'Subflow Fwd Packets': 2.0,
            'Subflow Fwd Bytes': 12.0,
            'Subflow Bwd Packets': 0.0,
            'Subflow Bwd Bytes': 0.0,
            'Init Fwd Win Bytes': 506.0,
            'Init Bwd Win Bytes': -1.0,
            'Fwd Act Data Packets': 1.0,
            'Fwd Seg Size Min': 20.0,
            'Active Mean': 0.0,
            'Active Std': 0.0,
            'Active Max': 0.0,
            'Active Min': 0.0,
            'Idle Mean': 0.0,
            'Idle Std': 0.0,
            'Idle Max': 0.0,
            'Idle Min': 0.0,
        }

        for _ in range(5):
            network_flow = processor.process_packet(packet)
            self.stdout.write(self.style.SUCCESS(f'Processed packet: {network_flow}'))
            time.sleep(1)
