# ids/services.py
import pandas as pd
import joblib
from django.conf import settings
from .models import NetworkFlow


class PacketProcessor:
    def __init__(self):
        # Load the trained model and preprocessing artifacts
        self.model = joblib.load(settings.BASE_DIR / 'ml_models/models/model.pkl')
        self.scaler = joblib.load(settings.BASE_DIR / 'ml_models/models/scaler.pkl')
        self.label_encoder = joblib.load(settings.BASE_DIR / 'ml_models/models/label_encoder.pkl')

    def extract_features(self, packet):
        # Placeholder for feature extraction
        # In a real IDS, you'd use Scapy to parse packets and extract features
        # For now, we assume the packet is a dictionary with the same features as test.csv
        features = {
            'Protocol': packet.get('Protocol', 0),
            'Flow Duration': packet.get('Flow Duration', 0),
            'Total Fwd Packets': packet.get('Total Fwd Packets', 0),
            'Total Backward Packets': packet.get('Total Backward Packets', 0),
            'Fwd Packets Length Total': packet.get('Fwd Packets Length Total', 0),
            'Bwd Packets Length Total': packet.get('Bwd Packets Length Total', 0),
            'Fwd Packet Length Max': packet.get('Fwd Packet Length Max', 0),
            'Fwd Packet Length Min': packet.get('Fwd Packet Length Min', 0),
            'Fwd Packet Length Mean': packet.get('Fwd Packet Length Mean', 0),
            'Fwd Packet Length Std': packet.get('Fwd Packet Length Std', 0),
            'Bwd Packet Length Max': packet.get('Bwd Packet Length Max', 0),
            'Bwd Packet Length Min': packet.get('Bwd Packet Length Min', 0),
            'Bwd Packet Length Mean': packet.get('Bwd Packet Length Mean', 0),
            'Bwd Packet Length Std': packet.get('Bwd Packet Length Std', 0),
            'Flow Bytes/s': packet.get('Flow Bytes/s', 0),
            'Flow Packets/s': packet.get('Flow Packets/s', 0),
            'Flow IAT Mean': packet.get('Flow IAT Mean', 0),
            'Flow IAT Std': packet.get('Flow IAT Std', 0),
            'Flow IAT Max': packet.get('Flow IAT Max', 0),
            'Flow IAT Min': packet.get('Flow IAT Min', 0),
            'Fwd IAT Total': packet.get('Fwd IAT Total', 0),
            'Fwd IAT Mean': packet.get('Fwd IAT Mean', 0),
            'Fwd IAT Std': packet.get('Fwd IAT Std', 0),
            'Fwd IAT Max': packet.get('Fwd IAT Max', 0),
            'Fwd IAT Min': packet.get('Fwd IAT Min', 0),
            'Bwd IAT Total': packet.get('Bwd IAT Total', 0),
            'Bwd IAT Mean': packet.get('Bwd IAT Mean', 0),
            'Bwd IAT Std': packet.get('Bwd IAT Std', 0),
            'Bwd IAT Max': packet.get('Bwd IAT Max', 0),
            'Bwd IAT Min': packet.get('Bwd IAT Min', 0),
            'Fwd PSH Flags': packet.get('Fwd PSH Flags', 0),
            'Fwd Header Length': packet.get('Fwd Header Length', 0),
            'Bwd Header Length': packet.get('Bwd Header Length', 0),
            'Fwd Packets/s': packet.get('Fwd Packets/s', 0),
            'Bwd Packets/s': packet.get('Bwd Packets/s', 0),
            'Packet Length Min': packet.get('Packet Length Min', 0),
            'Packet Length Max': packet.get('Packet Length Max', 0),
            'Packet Length Mean': packet.get('Packet Length Mean', 0),
            'Packet Length Std': packet.get('Packet Length Std', 0),
            'Packet Length Variance': packet.get('Packet Length Variance', 0),
            'FIN Flag Count': packet.get('FIN Flag Count', 0),
            'SYN Flag Count': packet.get('SYN Flag Count', 0),
            'RST Flag Count': packet.get('RST Flag Count', 0),
            'PSH Flag Count': packet.get('PSH Flag Count', 0),
            'ACK Flag Count': packet.get('ACK Flag Count', 0),
            'URG Flag Count': packet.get('URG Flag Count', 0),
            'ECE Flag Count': packet.get('ECE Flag Count', 0),
            'Down/Up Ratio': packet.get('Down/Up Ratio', 0),
            'Avg Packet Size': packet.get('Avg Packet Size', 0),
            'Avg Fwd Segment Size': packet.get('Avg Fwd Segment Size', 0),
            'Avg Bwd Segment Size': packet.get('Avg Bwd Segment Size', 0),
            'Subflow Fwd Packets': packet.get('Subflow Fwd Packets', 0),
            'Subflow Fwd Bytes': packet.get('Subflow Fwd Bytes', 0),
            'Subflow Bwd Packets': packet.get('Subflow Bwd Packets', 0),
            'Subflow Bwd Bytes': packet.get('Subflow Bwd Bytes', 0),
            'Init Fwd Win Bytes': packet.get('Init Fwd Win Bytes', 0),
            'Init Bwd Win Bytes': packet.get('Init Bwd Win Bytes', 0),
            'Fwd Act Data Packets': packet.get('Fwd Act Data Packets', 0),
            'Fwd Seg Size Min': packet.get('Fwd Seg Size Min', 0),
            'Active Mean': packet.get('Active Mean', 0),
            'Active Std': packet.get('Active Std', 0),
            'Active Max': packet.get('Active Max', 0),
            'Active Min': packet.get('Active Min', 0),
            'Idle Mean': packet.get('Idle Mean', 0),
            'Idle Std': packet.get('Idle Std', 0),
            'Idle Max': packet.get('Idle Max', 0),
            'Idle Min': packet.get('Idle Min', 0),
        }
        return features

    def predict(self, features):
        # Convert features to a DataFrame
        df = pd.DataFrame([features])

        # Scale the features
        X_scaled = self.scaler.transform(df)

        # Make prediction
        prediction = self.model.predict(X_scaled)

        # Decode the prediction
        predicted_label = self.label_encoder.inverse_transform(prediction)[0]
        return predicted_label

    def process_packet(self, packet):
        # Extract features from the packet
        features = self.extract_features(packet)

        # Make a prediction
        prediction = self.predict(features)

        # Save the network flow and prediction to the database
        network_flow = NetworkFlow(
            protocol=features['Protocol'],
            flow_duration=features['Flow Duration'],
            total_fwd_packets=features['Total Fwd Packets'],
            total_backward_packets=features['Total Backward Packets'],
            fwd_packets_length_total=features['Fwd Packets Length Total'],
            bwd_packets_length_total=features['Bwd Packets Length Total'],
            fwd_packet_length_max=features['Fwd Packet Length Max'],
            fwd_packet_length_min=features['Fwd Packet Length Min'],
            fwd_packet_length_mean=features['Fwd Packet Length Mean'],
            fwd_packet_length_std=features['Fwd Packet Length Std'],
            bwd_packet_length_max=features['Bwd Packet Length Max'],
            bwd_packet_length_min=features['Bwd Packet Length Min'],
            bwd_packet_length_mean=features['Bwd Packet Length Mean'],
            bwd_packet_length_std=features['Bwd Packet Length Std'],
            flow_bytes_s=features['Flow Bytes/s'],
            flow_packets_s=features['Flow Packets/s'],
            flow_iat_mean=features['Flow IAT Mean'],
            flow_iat_std=features['Flow IAT Std'],
            flow_iat_max=features['Flow IAT Max'],
            flow_iat_min=features['Flow IAT Min'],
            fwd_iat_total=features['Fwd IAT Total'],
            fwd_iat_mean=features['Fwd IAT Mean'],
            fwd_iat_std=features['Fwd IAT Std'],
            fwd_iat_max=features['Fwd IAT Max'],
            fwd_iat_min=features['Fwd IAT Min'],
            bwd_iat_total=features['Bwd IAT Total'],
            bwd_iat_mean=features['Bwd IAT Mean'],
            bwd_iat_std=features['Bwd IAT Std'],
            bwd_iat_max=features['Bwd IAT Max'],
            bwd_iat_min=features['Bwd IAT Min'],
            fwd_psh_flags=features['Fwd PSH Flags'],
            fwd_header_length=features['Fwd Header Length'],
            bwd_header_length=features['Bwd Header Length'],
            fwd_packets_s=features['Fwd Packets/s'],
            bwd_packets_s=features['Bwd Packets/s'],
            packet_length_min=features['Packet Length Min'],
            packet_length_max=features['Packet Length Max'],
            packet_length_mean=features['Packet Length Mean'],
            packet_length_std=features['Packet Length Std'],
            packet_length_variance=features['Packet Length Variance'],
            fin_flag_count=features['FIN Flag Count'],
            syn_flag_count=features['SYN Flag Count'],
            rst_flag_count=features['RST Flag Count'],
            psh_flag_count=features['PSH Flag Count'],
            ack_flag_count=features['ACK Flag Count'],
            urg_flag_count=features['URG Flag Count'],
            ece_flag_count=features['ECE Flag Count'],
            down_up_ratio=features['Down/Up Ratio'],
            avg_packet_size=features['Avg Packet Size'],
            avg_fwd_segment_size=features['Avg Fwd Segment Size'],
            avg_bwd_segment_size=features['Avg Bwd Segment Size'],
            subflow_fwd_packets=features['Subflow Fwd Packets'],
            subflow_fwd_bytes=features['Subflow Fwd Bytes'],
            subflow_bwd_packets=features['Subflow Bwd Packets'],
            subflow_bwd_bytes=features['Subflow Bwd Bytes'],
            init_fwd_win_bytes=features['Init Fwd Win Bytes'],
            init_bwd_win_bytes=features['Init Bwd Win Bytes'],
            fwd_act_data_packets=features['Fwd Act Data Packets'],
            fwd_seg_size_min=features['Fwd Seg Size Min'],
            active_mean=features['Active Mean'],
            active_std=features['Active Std'],
            active_max=features['Active Max'],
            active_min=features['Active Min'],
            idle_mean=features['Idle Mean'],
            idle_std=features['Idle Std'],
            idle_max=features['Idle Max'],
            idle_min=features['Idle Min'],
            prediction=prediction
        )
        network_flow.save()
        return network_flow
