# ml_models/train_neural_network.py
import pickle

import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
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

# Prepare features
features = ['packet_count', 'byte_count', 'duration', 'flow_rate', 'byte_rate']
df = df[features].fillna(0)

# Normalize the data
scaler = StandardScaler()
X = scaler.fit_transform(df)

# Build an autoencoder neural network for anomaly detection
model = tf.keras.Sequential([
    tf.keras.layers.Dense(16, activation='relu', input_shape=(X.shape[1],)),
    tf.keras.layers.Dense(8, activation='relu'),
    tf.keras.layers.Dense(16, activation='relu'),
    tf.keras.layers.Dense(X.shape[1], activation='linear')
])

model.compile(optimizer='adam', loss='mse')
model.fit(X, X, epochs=10, batch_size=32, validation_split=0.2, verbose=1)

# Save the model and scaler
model_path = os.path.join(os.path.dirname(__file__), 'neural_network_model')
model.save(model_path)
scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.pkl')
with open(scaler_path, 'wb') as f:
    pickle.dump(scaler, f)

print(f"Neural network model saved to {model_path}")
print(f"Scaler saved to {scaler_path}")