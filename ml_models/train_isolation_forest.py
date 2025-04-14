# ml_models/train_isolation_forest.py
import pandas as pd
import pickle
from sklearn.ensemble import IsolationForest
from django.core.wsgi import get_wsgi_application
import os
import sys
import django

# Set up Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'network_ids.settings')
django.setup()

from ids.models import NetworkFlow

# Fetch network flow data from the database
flows = NetworkFlow.objects.all().values('packet_count', 'byte_count', 'duration', 'flow_rate', 'byte_rate')
df = pd.DataFrame(flows)

# Prepare features (remove any None values)
features = ['packet_count', 'byte_count', 'duration', 'flow_rate', 'byte_rate']
df = df[features].fillna(0)

# Train an Isolation Forest model
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(df)

# Save the model in the ml_models/ directory
model_path = os.path.join(os.path.dirname(__file__), 'isolation_forest_model.pkl')
with open(model_path, 'wb') as f:
    pickle.dump(model, f)

print(f"Model trained and saved as {model_path}")