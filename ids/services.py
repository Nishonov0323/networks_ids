# services.py
import json
import logging

import numpy as np
from django.utils import timezone
from scapy.layers.inet import IP

from .models import NetworkFlow, Alert, DetectionRule, MLModel, HierarchicalModel

logger = logging.getLogger(__name__)


class PacketProcessor:
    # services.py (update process_packet method in PacketProcessor)
    def process_packet(self, packet_data):
        try:
            # Handle hex-encoded packet data from the API
            if isinstance(packet_data, dict) and 'raw_packet' in packet_data:
                # Decode hex string to bytes
                raw_packet = bytes.fromhex(packet_data['raw_packet'])
            else:
                raw_packet = packet_data

            packet = IP(raw_packet)

            # Extract basic packet information
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            # Extract ports (if TCP or UDP)
            src_port = dst_port = 0
            if protocol == 6 and packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif protocol == 17 and packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # Create or update a NetworkFlow object
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            flow, created = NetworkFlow.objects.get_or_create(
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=self.protocol_to_string(protocol),
                defaults={
                    'packet_count': 1,
                    'byte_count': len(packet),
                    'duration': 0.0,
                    'packet_data': json.dumps(packet.summary())
                }
            )

            if not created:
                # Update existing flow
                flow.packet_count += 1
                flow.byte_count += len(packet)
                flow.duration = (timezone.now() - flow.timestamp).total_seconds()
                flow.flow_rate = flow.packet_count / max(flow.duration, 1)
                flow.byte_rate = flow.byte_count / max(flow.duration, 1)
                flow.avg_packet_size = flow.byte_count / flow.packet_count
                flow.save()

            return flow

        except Exception as e:
            print(f"Error processing packet: {e}")
            return None

    def protocol_to_string(self, proto_num):
        """Convert protocol number to string."""
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return proto_map.get(proto_num, 'OTHER')

class DetectionService:
    def detect(self, flow):
        """
        Analyze a NetworkFlow object and detect potential cyberattacks.
        Returns: List of Alert objects if attacks are detected, empty list otherwise.
        """
        alerts = []

        # Rule-based detection
        alerts.extend(self.detect_with_rules(flow))

        # ML-based detection (placeholder for now)
        alerts.extend(self.detect_with_ml(flow))

        return alerts

    def detect_with_rules(self, flow):
        """Detect attacks using signature-based rules."""
        alerts = []
        rules = DetectionRule.objects.filter(enabled=True)

        for rule in rules:
            rule_details = json.loads(rule.rule_details) if rule.rule_details else {}

            # Example Rule 1: Detect high packet rate (possible DoS)
            if rule.name == "High Packet Rate (DoS)":
                threshold = rule_details.get('packet_rate_threshold', 100)  # Packets per second
                if flow.flow_rate and flow.flow_rate > threshold:
                    alert = Alert(
                        flow=flow,
                        rule=rule,
                        status='NEW',
                        confidence=0.9,
                        details=f"High packet rate detected: {flow.flow_rate} packets/sec",
                        attack_category='DOS',
                        attack_subcategory='Flooding'
                    )
                    alerts.append(alert)

            # Example Rule 2: Detect port scanning (reconnaissance)
            if rule.name == "Port Scan Detection":
                # Check for flows from the same source IP to multiple destination ports
                recent_flows = NetworkFlow.objects.filter(
                    source_ip=flow.source_ip,
                    timestamp__gte=flow.timestamp - timezone.timedelta(minutes=5)
                )
                unique_dst_ports = recent_flows.values('destination_port').distinct().count()
                port_threshold = rule_details.get('port_threshold', 10)
                if unique_dst_ports > port_threshold:
                    alert = Alert(
                        flow=flow,
                        rule=rule,
                        status='NEW',
                        confidence=0.85,
                        details=f"Port scanning detected: {unique_dst_ports} unique ports in 5 minutes",
                        attack_category='RECON',
                        attack_subcategory='Port Scan'
                    )
                    alerts.append(alert)

        return alerts

    def detect_with_ml(self, flow):
        """Placeholder for ML-based anomaly detection."""
        # TODO: Integrate MLModel or HierarchicalModel for anomaly detection
        return []


class FeatureExtractor:
    """Service for extracting features from network flows for analysis"""

    def extract_basic_features(self, flow):
        """Extract basic numerical features from a flow"""
        features = {
            'duration': flow.duration,
            'protocol_tcp': 1 if flow.protocol.lower() == 'tcp' else 0,
            'protocol_udp': 1 if flow.protocol.lower() == 'udp' else 0,
            'protocol_icmp': 1 if flow.protocol.lower() == 'icmp' else 0,
            'packet_count': flow.packet_count,
            'byte_count': flow.byte_count,
            'avg_packet_size': flow.avg_packet_size or 0,
            'flow_rate': flow.flow_rate or 0,
            'byte_rate': flow.byte_rate or 0,
            'is_wellknown_port': 1 if flow.destination_port < 1024 else 0
        }
        return features

    def extract_advanced_features(self, flow):
        """Extract more advanced features including those from packet content"""
        basic_features = self.extract_basic_features(flow)

        # Try to extract advanced features from packet data if available
        advanced_features = {}

        try:
            packet_data = flow.get_packet_data()

            if packet_data and len(packet_data) > 0:
                # Extract features from packet headers
                # This is a placeholder - implement based on your packet format
                tcp_flags_counts = {'SYN': 0, 'ACK': 0, 'FIN': 0, 'RST': 0, 'PSH': 0, 'URG': 0}

                for packet in packet_data:
                    flags = packet.get('tcp_flags', {})
                    for flag, count in tcp_flags_counts.items():
                        if flags.get(flag.lower(), False):
                            tcp_flags_counts[flag] += 1

                # Add TCP flag features
                for flag, count in tcp_flags_counts.items():
                    advanced_features[f'tcp_{flag.lower()}_count'] = count
                    advanced_features[f'tcp_{flag.lower()}_ratio'] = count / len(packet_data) if len(
                        packet_data) > 0 else 0

                # Inter-arrival time statistics
                if len(packet_data) > 1:
                    arrival_times = [p.get('timestamp') for p in packet_data if p.get('timestamp')]
                    if len(arrival_times) > 1:
                        arrival_diffs = [(arrival_times[i + 1] - arrival_times[i]).total_seconds()
                                         for i in range(len(arrival_times) - 1)]
                        advanced_features['iat_mean'] = np.mean(arrival_diffs) if arrival_diffs else 0
                        advanced_features['iat_std'] = np.std(arrival_diffs) if arrival_diffs else 0
                        advanced_features['iat_max'] = max(arrival_diffs) if arrival_diffs else 0
                        advanced_features['iat_min'] = min(arrival_diffs) if arrival_diffs else 0

        except Exception as e:
            logger.warning(f"Error extracting advanced features: {str(e)}")

        # Combine basic and advanced features
        all_features = {**basic_features, **advanced_features}
        return all_features


class DetectionService:
    """Service for detecting intrusions using various methods"""

    def __init__(self):
        self.feature_extractor = FeatureExtractor()

    def analyze_flow(self, flow):
        """Analyze a network flow using all available detection methods"""
        # Check against signature-based rules
        signature_alerts = self.signature_based_detection(flow)

        # Extract features for ML-based detection
        features = self.feature_extractor.extract_advanced_features(flow)

        # Run anomaly detection
        anomaly_alerts = self.anomaly_detection(flow, features)

        # Run ML-based detection
        ml_alerts = self.ml_based_detection(flow, features)

        # Run hierarchical model detection
        hierarchical_alerts = self.hierarchical_detection(flow, features)

        # Combine all alerts (could implement alert correlation here)
        all_alerts = signature_alerts + anomaly_alerts + ml_alerts + hierarchical_alerts

        return all_alerts

    def signature_based_detection(self, flow):
        """Detect intrusions using signature-based rules"""
        alerts = []

        # Get all enabled signature-based rules
        rules = DetectionRule.objects.filter(rule_type='SIGNATURE', enabled=True)

        for rule in rules:
            rule_details = rule.get_rule_details()

            # Example implementation of a signature match
            # This should be customized based on your rule format
            match = False

            # Check IP-based rules
            if 'source_ip' in rule_details and rule_details['source_ip'] == flow.source_ip:
                match = True

            if 'destination_ip' in rule_details and rule_details['destination_ip'] == flow.destination_ip:
                match = True

            # Check port-based rules
            if 'destination_port' in rule_details and rule_details['destination_port'] == flow.destination_port:
                match = True

            # Check packet content if rule includes payload patterns
            if 'payload_pattern' in rule_details and flow.packet_data:
                packet_data = flow.get_packet_data()
                for packet in packet_data:
                    payload = packet.get('payload', '')
                    if rule_details['payload_pattern'] in payload:
                        match = True
                        break

            if match:
                alert = Alert(
                    flow=flow,
                    rule=rule,
                    status='NEW',
                    timestamp=timezone.now(),
                    confidence=1.0,  # Signature-based rules are deterministic
                    attack_category=rule_details.get('attack_category'),
                    attack_subcategory=rule_details.get('attack_subcategory'),
                    details=f"Signature-based detection: Rule {rule.name} matched"
                )
                alert.save()
                alerts.append(alert)

        return alerts

    def anomaly_detection(self, flow, features):
        """Detect intrusions using anomaly detection"""
        alerts = []

        # Get all enabled anomaly-based rules
        rules = DetectionRule.objects.filter(rule_type='ANOMALY', enabled=True)

        for rule in rules:
            rule_details = rule.get_rule_details()

            # Example implementation of anomaly detection
            # This should be customized based on your anomaly detection approach
            anomaly_detected = False
            confidence = 0.0

            # Check for traffic volume anomalies
            if 'max_flow_rate' in rule_details and features['flow_rate'] > rule_details['max_flow_rate']:
                anomaly_detected = True
                confidence = min(1.0, features['flow_rate'] / rule_details['max_flow_rate'])

            # Check for protocol anomalies
            if 'expected_protocol' in rule_details and flow.protocol != rule_details['expected_protocol']:
                anomaly_detected = True
                confidence = 0.9  # High confidence for protocol mismatch

            if anomaly_detected:
                alert = Alert(
                    flow=flow,
                    rule=rule,
                    status='NEW',
                    timestamp=timezone.now(),
                    confidence=confidence,
                    attack_category=rule_details.get('attack_category', 'GENERIC'),
                    attack_subcategory=rule_details.get('attack_subcategory'),
                    details=f"Anomaly detection: Rule {rule.name} triggered with confidence {confidence:.2f}"
                )
                alert.save()
                alerts.append(alert)

        return alerts

    def ml_based_detection(self, flow, features):
        """Detect intrusions using machine learning models"""
        alerts = []

        # Placeholder for ML model loading and prediction
        # In a real implementation, you'd load trained models and make predictions

        # Get all enabled ML-based rules
        rules = DetectionRule.objects.filter(rule_type='ML', enabled=True)

        for rule in rules:
            rule_details = rule.get_rule_details()

            if 'model_id' in rule_details:
                try:
                    # Get the associated ML model
                    model = MLModel.objects.get(id=rule_details['model_id'])

                    # Here you would load the model using model.model_path
                    # and make predictions
                    # This is just a placeholder
                    prediction = 0  # 0 = normal, 1 = attack
                    confidence = 0.0

                    # Simulate a prediction for demonstration
                    if features['flow_rate'] > 100 and features['protocol_tcp'] == 1:
                        prediction = 1
                        confidence = 0.85

                    if prediction == 1 and confidence >= rule_details.get('min_confidence', 0.5):
                        alert = Alert(
                            flow=flow,
                            rule=rule,
                            status='NEW',
                            timestamp=timezone.now(),
                            confidence=confidence,
                            attack_category=rule_details.get('attack_category', 'GENERIC'),
                            attack_subcategory=rule_details.get('attack_subcategory'),
                            details=f"ML detection: Model {model.name} predicted attack with confidence {confidence:.2f}"
                        )
                        alert.save()
                        alerts.append(alert)

                except MLModel.DoesNotExist:
                    logger.error(f"ML model with ID {rule_details['model_id']} not found")
                    continue
                except Exception as e:
                    logger.error(f"Error in ML-based detection: {str(e)}")
                    continue

        return alerts

    def hierarchical_detection(self, flow, features):
        """Detect intrusions using hierarchical models"""
        alerts = []

        # Get all enabled hierarchical models
        hierarchical_models = HierarchicalModel.objects.filter(enabled=True)

        for h_model in hierarchical_models:
            try:
                # Get the hierarchical structure
                structure = h_model.get_structure()

                # This is placeholder code for hierarchical detection
                # In a real implementation, you would:
                # 1. Apply the first-level classifier to determine attack/normal
                # 2. If attack, apply second-level classifier to determine attack category
                # 3. Finally, apply specific attack classifiers

                # For demonstration, simulate a hierarchical detection
                is_attack = features['flow_rate'] > 50
                attack_category = None
                attack_subcategory = None
                confidence = 0.0

                if is_attack:
                    confidence = min(1.0, features['flow_rate'] / 100)

                    # Determine attack category
                    if features['protocol_tcp'] == 1 and features['is_wellknown_port'] == 1:
                        attack_category = 'R2L'  # Remote to Local

                        # Determine attack subcategory
                        if features.get('tcp_syn_ratio', 0) > 0.8:
                            attack_subcategory = 'SQL Injection'
                        else:
                            attack_subcategory = 'Brute Force'

                    elif features['protocol_tcp'] == 1 and features['flow_rate'] > 200:
                        attack_category = 'DOS'  # Denial of Service
                        attack_subcategory = 'TCP Flood'

                    elif features['protocol_udp'] == 1:
                        attack_category = 'DOS'  # Denial of Service
                        attack_subcategory = 'UDP Flood'

                if is_attack and confidence >= 0.6:
                    # Create a rule instance for the alert
                    rule, created = DetectionRule.objects.get_or_create(
                        name=f"Hierarchical: {h_model.name}",
                        rule_type='ML',
                        defaults={
                            'description': f"Auto-generated rule for hierarchical model {h_model.name}",
                            'rule_details': json.dumps({'model_id': str(h_model.id)}),
                            'severity': 3
                        }
                    )

                    alert = Alert(
                        flow=flow,
                        rule=rule,
                        status='NEW',
                        timestamp=timezone.now(),
                        confidence=confidence,
                        attack_category=attack_category,
                        attack_subcategory=attack_subcategory,
                        details=f"Hierarchical detection: Model {h_model.name} predicted {attack_category}/{attack_subcategory} with confidence {confidence:.2f}"
                    )
                    alert.save()
                    alerts.append(alert)

            except Exception as e:
                logger.error(f"Error in hierarchical detection: {str(e)}")
                continue

        return alerts
