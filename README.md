# Network Intrusion Detection System (NIDS)

A Django-based network intrusion detection system with hierarchical machine learning capabilities.

## Features

- Real-time network traffic monitoring
- Signature-based detection
- Anomaly-based detection
- Machine learning-based detection
- Hierarchical multi-stage classification
- RESTful API for integration
- Dashboard for monitoring and analysis

## Installation

1. Clone the repository
2. Install the requirements: `pip install -r requirements.txt`
3. Run migrations: `python manage.py migrate`
4. Create a superuser: `python manage.py createsuperuser`
5. Run the server: `python manage.py runserver`

## Running the Packet Capture

To start monitoring network traffic:

```bash
python manage.py run_packet_capture start --interface eth0
```
## Machine Learning Models

The system uses a hierarchical multi-stage approach for intrusion detection:
1. Binary classification (Normal vs. Attack)
2. Attack category classification
3. Specific attack type classification

## API Endpoints

- `/api/flows/` - Network flow data
- `/api/alerts/` - IDS alerts
- `/api/rules/` - Detection rules
- `/api/models/` - Machine learning models
- `/api/hierarchical-models/` - Hierarchical models
- `/api/training-jobs/` - Model training jobs
- `/api/interfaces/` - Network interfaces
- `/api/ingest/` - Packet ingestion endpoint
- `/api/statistics/` - System statistics

## Dashboard

Access the dashboard at:
- `/` - Main dashboard
