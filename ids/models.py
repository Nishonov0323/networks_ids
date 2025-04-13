# D:\Python\networks_ids\ids\models.py
from django.db import models
import uuid
import json
from django.utils import timezone


class NetworkFlow(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.IntegerField()
    destination_port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    packet_count = models.IntegerField()
    byte_count = models.IntegerField()
    timestamp = models.DateTimeField(default=timezone.now)
    duration = models.FloatField(help_text="Flow duration in seconds")
    avg_packet_size = models.FloatField(null=True, blank=True)
    flow_rate = models.FloatField(null=True, blank=True, help_text="Packets per second")
    byte_rate = models.FloatField(null=True, blank=True, help_text="Bytes per second")
    packet_data = models.TextField(null=True, blank=True, help_text="JSON representation of packet data")

    def get_packet_data(self):
        if self.packet_data:
            return json.loads(self.packet_data)
        return {}

    def __str__(self):
        return f"{self.source_ip}:{self.source_port} → {self.destination_ip}:{self.destination_port} ({self.protocol})"


class DetectionRule(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField()
    RULE_TYPES = (('SIGNATURE', 'Signature-based'), ('ANOMALY', 'Anomaly-based'), ('ML', 'Machine learning-based'))
    rule_type = models.CharField(max_length=20, choices=RULE_TYPES)
    rule_details = models.TextField(help_text="JSON representation of rule parameters")
    severity = models.IntegerField(default=1, help_text="1-5 scale, 5 being most severe")
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def get_rule_details(self):
        return json.loads(self.rule_details)

    def __str__(self):
        return f"{self.name} ({self.get_rule_type_display()})"


class Alert(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    flow = models.ForeignKey(NetworkFlow, on_delete=models.CASCADE, related_name='alerts')
    rule = models.ForeignKey(DetectionRule, on_delete=models.SET_NULL, null=True, related_name='alerts')
    STATUS_CHOICES = (('NEW', 'New'), ('INVESTIGATING', 'Under Investigation'), ('RESOLVED', 'Resolved'),
                      ('FALSE_POSITIVE', 'False Positive'))
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='NEW')
    timestamp = models.DateTimeField(default=timezone.now)
    confidence = models.FloatField(default=1.0, help_text="Confidence score (0-1)")
    details = models.TextField(null=True, blank=True, help_text="Additional alert details")
    ATTACK_CATEGORIES = (
    ('RECON', 'Reconnaissance'), ('DOS', 'Denial of Service'), ('U2R', 'User to Root'), ('R2L', 'Remote to Local'),
    ('PROBE', 'Probing'), ('BACKDOOR', 'Backdoor'), ('SHELLCODE', 'Shellcode'), ('WORM', 'Worm'),
    ('GENERIC', 'Generic'), ('ANALYSIS', 'Analysis'), ('FUZZERS', 'Fuzzers'), ('EXPLOIT', 'Exploit'),
    ('OTHER', 'Other'))
    attack_category = models.CharField(max_length=20, choices=ATTACK_CATEGORIES, null=True, blank=True)
    attack_subcategory = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return f"Alert: {self.rule.name if self.rule else 'Unknown'} at {self.timestamp}"


class MLModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField()
    MODEL_TYPES = (('CLASSIFIER', 'Classifier'), ('ANOMALY', 'Anomaly Detector'), ('ENSEMBLE', 'Ensemble Model'),
                   ('HIERARCHICAL', 'Hierarchical Model'))
    model_type = models.CharField(max_length=20, choices=MODEL_TYPES)
    model_path = models.CharField(max_length=255)
    parameters = models.TextField(help_text="JSON representation of model parameters")
    accuracy = models.FloatField(null=True, blank=True)
    precision = models.FloatField(null=True, blank=True)
    recall = models.FloatField(null=True, blank=True)
    f1_score = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def get_parameters(self):
        return json.loads(self.parameters)

    def __str__(self):
        return f"{self.name} ({self.get_model_type_display()})"


class TrainingJob(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    model = models.ForeignKey(MLModel, on_delete=models.CASCADE, related_name='training_jobs')
    STATUS_CHOICES = (('PENDING', 'Pending'), ('RUNNING', 'Running'), ('COMPLETED', 'Completed'), ('FAILED', 'Failed'))
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    dataset_info = models.TextField(help_text="JSON representation of dataset information")
    training_parameters = models.TextField(help_text="JSON representation of training parameters")
    results = models.TextField(null=True, blank=True, help_text="JSON representation of training results")

    def get_dataset_info(self):
        return json.loads(self.dataset_info)

    def get_training_parameters(self):
        return json.loads(self.training_parameters)

    def get_results(self):
        if self.results:
            return json.loads(self.results)
        return {}

    def __str__(self):
        return f"Training job for {self.model.name} - {self.get_status_display()}"


class HierarchicalModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField()
    structure = models.TextField(help_text="JSON representation of hierarchical model structure")
    modelss = models.ManyToManyField(MLModel, related_name='hierarchical_models')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    enabled = models.BooleanField(default=True)

    def get_structure(self):
        return json.loads(self.structure)

    def __str__(self):
        return f"Hierarchical Model: {self.name}"


class NetworkInterface(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    interface_type = models.CharField(max_length=50)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    mac_address = models.CharField(max_length=17, null=True, blank=True)
    is_monitoring = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.name} ({self.ip_address or 'No IP'})"
