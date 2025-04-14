# ml_models/utils.py
import pandas as pd
from django.core.wsgi import get_wsgi_application
import os
import sys
import django

# Set up Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'network_ids.settings')
django.setup()

from ids.models import NetworkFlow


def load_flow_data():
    """Load network flow data from the database into a DataFrame."""
    flows = NetworkFlow.objects.all().values('packet_count', 'byte_count', 'duration', 'flow_rate', 'byte_rate')
    df = pd.DataFrame(flows)
    features = ['packet_count', 'byte_count', 'duration', 'flow_rate', 'byte_rate']
    df = df[features].fillna(0)
    return df


def evaluate_model(model, data):
    """Evaluate an anomaly detection model (placeholder)."""
    # Example: Calculate reconstruction error for autoencoders or anomaly scores
    pass
