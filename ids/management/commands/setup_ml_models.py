# ids/management/commands/setup_ml_models.py
from django.core.management.base import BaseCommand
from ids.models import MLModel
import os

class Command(BaseCommand):
    help = 'Set up ML models in the database'

    def handle(self, *args, **kwargs):
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'ml_models'))

        # Isolation Forest Model
        MLModel.objects.update_or_create(
            name="Isolation Forest Anomaly Detector",
            defaults={
                'description': 'Isolation Forest for anomaly detection',
                'model_type': 'ANOMALY',
                'model_path': os.path.join(base_path, 'isolation_forest_model.pkl'),
                'parameters': '{"contamination": 0.1}',
                'enabled': True
            }
        )

        # Neural Network Model
        MLModel.objects.update_or_create(
            name="Neural Network Anomaly Detector",
            defaults={
                'description': 'Neural Network (Autoencoder) for anomaly detection',
                'model_type': 'ANOMALY',
                'model_path': os.path.join(base_path, 'neural_network_model'),
                'parameters': '{"threshold": 0.1}',
                'enabled': True
            }
        )

        self.stdout.write(self.style.SUCCESS('Successfully set up ML models'))