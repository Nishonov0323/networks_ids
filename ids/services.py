# services.py
import numpy as np
import json
import logging
from datetime import datetime
from django.utils import timezone
from .models import NetworkFlow, Alert, DetectionRule, MLModel, HierarchicalModel

logger = logging.getLogger(__name__)


class PacketProcessor:
    """Service for processing incoming network packets and creating flow data"""

    def __init__(self):
        self.active_flows = {}  # Store active flows by key

    def process_packet(self, packet_data):
        """Process a raw network packet and update flow information"""
        # Extract key fields from packet
        try:
            src_ip = packet_data.get('src_ip')
            dst_ip = packet_data.get('dst_ip')
            src_port = packet_data.get('src_port')
            dst_port = packet_data.get('dst_port')
            protocol = packet_data.get('protocol', 'unknown')
            packet_size = packet_data.get('size', 0)
            timestamp = packet_data.get('timestamp', timezone.now())

            # Create a flow key (bidirectional)
            if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
                direction = 'forward'
            else:
                flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
                direction = 'backward'

            # Update or create flow
            if flow_key in self.active_flows:
                flow = self.active_flows[flow_key]
                flow['packet_count'] += 1
                flow['byte_count'] += packet_size
                flow['last_seen'] = timestamp
                flow['packets'].append(packet_data)

                # Update direction-specific counts
                if direction == 'forward':
                    flow['fwd_packet_count'] += 1
                    flow['fwd_byte_count'] += packet_size
                else:
                    flow['bwd_packet_count'] += 1
                    flow['bwd_byte_count'] += packet_size
            else:
                # Create new flow
                flow = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'start_time': timestamp,
                    'last_seen': timestamp,
                    'packet_count': 1,
                    'byte_count': packet_size,
                    'fwd_packet_count': 1 if direction == 'forward' else 0,
                    'fwd_byte_count': packet_size if direction == 'forward' else 0,
                    'bwd_packet_count': 1 if direction == 'backward' else 0,
                    'bwd_byte_count': packet_size if direction == 'backward' else 0,
                    'packets': [packet_data]
                }
                self.active_flows[flow_key] = flow

            # Check for flow timeout to save completed flows
            self._check_flow_timeouts()

            return flow_key

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
            return None

    def _check_flow_timeouts(self, timeout_seconds=120):
        """Check for flow timeouts and save completed flows"""
        current_time = timezone.now()
        timeout_flows = []

        for flow_key, flow in self.active_flows.items():
            last_seen = flow['last_seen']
            if (current_time - last_seen).total_seconds() > timeout_seconds:
                timeout_flows.append(flow_key)

        # Save and remove timed out flows
        for flow_key in timeout_flows:
            flow = self.active_flows.pop(flow_key)
            self._save_flow(flow)

    def _save_flow(self, flow):
        """Save a flow to the database"""
        try:
            duration = (flow['last_seen'] - flow['start_time']).total_seconds()
            avg_packet_size = flow['byte_count'] / flow['packet_count'] if flow['packet_count'] > 0 else 0
            flow_rate = flow['packet_count'] / duration if duration > 0 else 0
            byte_rate = flow['byte_count'] / duration if duration > 0 else 0

            # Keep just the first 10 packets to avoid excessive storage
            packet_data = json.dumps(flow['packets'][:10]) if flow['packets'] else None

            network_flow = NetworkFlow(
                source_ip=flow['src_ip'],
                destination_ip=flow['dst_ip'],
                source_port=flow['src_port'],
                destination_port=flow['dst_port'],
                protocol=flow['protocol'],
                packet_count=flow['packet_count'],
                byte_count=flow['byte_count'],
                timestamp=flow['start_time'],
                duration=duration,
                avg_packet_size=avg_packet_size,
                flow_rate=flow_rate,
                byte_rate=byte_rate,
                packet_data=packet_data
            )
            network_flow.save()

            # Run flow through detection pipeline
            DetectionService().analyze_flow(network_flow)

            return network_flow.id

        except Exception as e:
            logger.error(f"Error saving flow: {str(e)}")
            return None


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