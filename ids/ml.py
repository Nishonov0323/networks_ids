# ml.py
import numpy as np
import pandas as pd
import pickle
import os
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

logger = logging.getLogger(__name__)


class HierarchicalIDSModel:
    """Hierarchical Intrusion Detection System model based on the multi-stage approach"""

    def __init__(self, model_path=None):
        """Initialize the hierarchical model"""
        # Model components
        self.binary_model = None  # Binary classifier: Normal vs Attack
        self.category_model = None  # Attack category classifier
        self.subcategory_models = {}  # Specific attack type classifiers per category

        # Feature preprocessing
        self.binary_scaler = None
        self.category_scaler = None
        self.subcategory_scalers = {}

        # Model path
        self.model_path = model_path

        # Load model if path is provided
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)

    def train(self, X, y, test_size=0.2, random_state=42):
        """Train the hierarchical IDS model"""
        logger.info("Starting hierarchical model training...")

        # Prepare hierarchical labels
        binary_labels = self._create_binary_labels(y)
        category_labels = self._create_category_labels(y)
        subcategory_labels = self._create_subcategory_labels(y)

        # Split data
        X_train, X_test, y_train_binary, y_test_binary = train_test_split(
            X, binary_labels, test_size=test_size, random_state=random_state
        )

        # Train binary classifier (Normal vs Attack)
        logger.info("Training binary classifier...")
        self.binary_scaler = StandardScaler()
        X_train_scaled = self.binary_scaler.fit_transform(X_train)
        X_test_scaled = self.binary_scaler.transform(X_test)

        self.binary_model = RandomForestClassifier(n_estimators=100, random_state=random_state)
        self.binary_model.fit(X_train_scaled, y_train_binary)

        # Evaluate binary classifier
        y_pred_binary = self.binary_model.predict(X_test_scaled)
        binary_accuracy = accuracy_score(y_test_binary, y_pred_binary)
        logger.info(f"Binary classifier accuracy: {binary_accuracy:.4f}")

        # Filter only attack data for category classification
        attack_indices_train = np.where(y_train_binary == 1)[0]
        attack_indices_test = np.where(y_test_binary == 1)[0]

        if len(attack_indices_train) > 0 and len(attack_indices_test) > 0:
            X_train_attacks = X_train[attack_indices_train]
            X_test_attacks = X_test[attack_indices_test]
            y_train_category = category_labels[attack_indices_train]
            y_test_category = category_labels[attack_indices_test]

            # Train category classifier
            logger.info("Training attack category classifier...")
            self.category_scaler = StandardScaler()
            X_train_attacks_scaled = self.category_scaler.fit_transform(X_train_attacks)
            X_test_attacks_scaled = self.category_scaler.transform(X_test_attacks)

            self.category_model = RandomForestClassifier(n_estimators=100, random_state=random_state)
            self.category_model.fit(X_train_attacks_scaled, y_train_category)

            # Evaluate category classifier
            y_pred_category = self.category_model.predict(X_test_attacks_scaled)
            category_accuracy = accuracy_score(y_test_category, y_pred_category)
            logger.info(f"Category classifier accuracy: {category_accuracy:.4f}")

            # Train subcategory classifiers for each attack category
            unique_categories = np.unique(y_train_category)

            for category in unique_categories:
                cat_indices_train = np.where(y_train_category == category)[0]

                if len(cat_indices_train) > 10:  # Ensure enough samples
                    X_train_cat = X_train_attacks[cat_indices_train]
                    y_train_subcat = subcategory_labels[attack_indices_train][cat_indices_train]

                    # Check if we have multiple subcategories in this category
                    if len(np.unique(y_train_subcat)) > 1:
                        logger.info(f"Training subcategory classifier for {category}...")

                        # Create and train scaler
                        self.subcategory_scalers[category] = StandardScaler()
                        X_train_cat_scaled = self.subcategory_scalers[category].fit_transform(X_train_cat)

                        # Create and train subcategory model
                        subcat_model = RandomForestClassifier(n_estimators=100, random_state=random_state)
                        subcat_model.fit(X_train_cat_scaled, y_train_subcat)
                        self.subcategory_models[category] = subcat_model

        logger.info("Hierarchical model training completed")
        return {
            'binary_accuracy': binary_accuracy,
            'category_accuracy': category_accuracy if 'category_accuracy' in locals() else None
        }

    def predict(self, X):
        """Make hierarchical predictions"""
        if self.binary_model is None:
            raise ValueError("Model not trained. Call train() first.")

        results = []

        # Scale the input features
        X_scaled = self.binary_scaler.transform(X)

        # Binary prediction (Normal vs Attack)
        binary_preds = self.binary_model.predict(X_scaled)
        binary_probs = self.binary_model.predict_proba(X_scaled)

        for i, is_attack in enumerate(binary_preds):
            result = {
                'is_attack': bool(is_attack),
                'binary_confidence': binary_probs[i][int(is_attack)],
                'category': None,
                'category_confidence': None,
                'subcategory': None,
                'subcategory_confidence': None
            }

            # If classified as an attack and we have a category model
            if is_attack and self.category_model is not None:
                # Scale with category scaler
                X_i_cat_scaled = self.category_scaler.transform(X[i:i + 1])

                # Predict attack category
                category_pred = self.category_model.predict(X_i_cat_scaled)[0]
                category_probs = self.category_model.predict_proba(X_i_cat_scaled)[0]
                category_confidence = max(category_probs)

                result['category'] = category_pred
                result['category_confidence'] = category_confidence

                # If we have a subcategory model for this category
                if category_pred in self.subcategory_models:
                    # Scale with subcategory scaler
                    X_i_subcat_scaled = self.subcategory_scalers[category_pred].transform(X[i:i + 1])

                    # Predict attack subcategory
                    subcat_model = self.subcategory_models[category_pred]
                    subcat_pred = subcat_model.predict(X_i_subcat_scaled)[0]
                    subcat_probs = subcat_model.predict_proba(X_i_subcat_scaled)[0]
                    subcat_confidence = max(subcat_probs)

                    result['subcategory'] = subcat_pred
                    result['subcategory_confidence'] = subcat_confidence

            results.append(result)

        return results

    def save_model(self, path):
        """Save the hierarchical model to disk"""
        model_dict = {
            'binary_model': self.binary_model,
            'category_model': self.category_model,
            'subcategory_models': self.subcategory_models,
            'binary_scaler': self.binary_scaler,
            'category_scaler': self.category_scaler,
            'subcategory_scalers': self.subcategory_scalers
        }

        with open(path, 'wb') as f:
            pickle.dump(model_dict, f)

        self.model_path = path
        logger.info(f"Model saved to {path}")

    def load_model(self, path):
        """Load a hierarchical model from disk"""
        with open(path, 'rb') as f:
            model_dict = pickle.load(f)

        self.binary_model = model_dict['binary_model']
        self.category_model = model_dict['category_model']
        self.subcategory_models = model_dict['subcategory_models']
        self.binary_scaler = model_dict['binary_scaler']
        self.category_scaler = model_dict['category_scaler']
        self.subcategory_scalers = model_dict['subcategory_scalers']

        self.model_path = path
        logger.info(f"Model loaded from {path}")

    def _create_binary_labels(self, labels):
        """Create binary labels (0 for normal, 1 for attack)"""
        return np.where(labels == 'NORMAL', 0, 1)

    def _create_category_labels(self, labels):
        """Create category labels by mapping attacks to categories"""
        # This is a simplified example - customize for your dataset
        category_mapping = {
            'NORMAL': 'NORMAL',
            'DOS': 'DOS',
            'DDOS': 'DOS',
            'PROBE': 'PROBE',
            'R2L': 'R2L',
            'U2R': 'U2R',
            'BACKDOOR': 'BACKDOOR',
            'INJECTION': 'R2L',
            'XSS': 'R2L',
            'SCANNING': 'PROBE',
            # Add more mappings as needed
        }

        # Map each label to its category, default to label itself
        return np.array([category_mapping.get(label, label) for label in labels])

    def _create_subcategory_labels(self, labels):
        """Use original labels as subcategories"""
        return labels


class MLModelManager:
    """Manager for ML models used in the IDS"""

    def __init__(self, models_dir='ml_models'):
        """Initialize the ML model manager"""
        self.models_dir = models_dir
        self.models = {}

        # Create models directory if it doesn't exist
        os.makedirs(models_dir, exist_ok=True)

    def train_model(self, model_name, X, y, model_type='hierarchical', **params):
        """Train a new ML model"""
        if model_type == 'hierarchical':
            model = HierarchicalIDSModel()
            metrics = model.train(X, y, **params)

            # Save the trained model
            model_path = os.path.join(self.models_dir, f"{model_name}.pkl")
            model.save_model(model_path)

            # Store model in memory
            self.models[model_name] = model

            return {
                'model_name': model_name,
                'model_path': model_path,
                'metrics': metrics
            }
        else:
            raise ValueError(f"Unsupported model type: {model_type}")

    def load_model(self, model_name):
        """Load a model by name"""
        if model_name in self.models:
            return self.models[model_name]

        model_path = os.path.join(self.models_dir, f"{model_name}.pkl")

        if not os.path.exists(model_path):
            raise ValueError(f"Model not found: {model_name}")

        model = HierarchicalIDSModel(model_path)
        self.models[model_name] = model
        return model

    def predict(self, model_name, X):
        """Make predictions using a model"""
        model = self.load_model(model_name)
        return model.predict(X)

    def list_models(self):
        """List all available models"""
        model_files = [f[:-4] for f in os.listdir(self.models_dir) if f.endswith('.pkl')]
        return model_files


# Feature extraction utility for ML models
def extract_features_for_ml(flow):
    """Extract features from a flow for use with ML models"""
    # Basic features
    features = {
        'duration': flow.duration,
        'protocol_tcp': 1 if flow.protocol.lower() == 'tcp' else 0,
        'protocol_udp': 1 if flow.protocol.lower() == 'udp' else 0,
        'protocol_icmp': 1 if flow.protocol.lower() == 'icmp' else 0,
        'pkt_count': flow.packet_count,
        'byte_count': flow.byte_count,
        'pkt_rate': flow.flow_rate or 0,
        'byte_rate': flow.byte_rate or 0,
        'avg_pkt_size': flow.avg_packet_size or 0,
    }

    # Add port-based features
    features['src_port'] = flow.source_port
    features['dst_port'] = flow.destination_port
    features['is_wellknown_port'] = 1 if flow.destination_port < 1024 else 0

    # Advanced features from packet data if available
    packet_data = flow.get_packet_data()
    if packet_data:
        # TCP Flags if present
        tcp_flags = {'syn': 0, 'ack': 0, 'fin': 0, 'rst': 0, 'psh': 0, 'urg': 0}

        for packet in packet_data:
            flags = packet.get('tcp_flags', {})
            for flag in tcp_flags:
                if flags.get(flag, False):
                    tcp_flags[flag] += 1

        # Add TCP flag counts to features
        for flag, count in tcp_flags.items():
            features[f'tcp_{flag}_count'] = count
            features[f'tcp_{flag}_ratio'] = count / len(packet_data) if len(packet_data) > 0 else 0

    # Convert to numpy array
    feature_names = sorted(features.keys())
    feature_values = [features[name] for name in feature_names]

    return np.array([feature_values]), feature_names