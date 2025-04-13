# serializers.py
from rest_framework import serializers
from .models import NetworkFlow, Alert, DetectionRule, MLModel, HierarchicalModel, TrainingJob, NetworkInterface


class NetworkFlowSerializer(serializers.ModelSerializer):
    alert_count = serializers.SerializerMethodField()

    class Meta:
        model = NetworkFlow
        fields = [
            'id', 'source_ip', 'destination_ip', 'source_port', 'destination_port',
            'protocol', 'packet_count', 'byte_count', 'timestamp', 'duration',
            'avg_packet_size', 'flow_rate', 'byte_rate', 'packet_data', 'alert_count'
        ]

    def get_alert_count(self, obj):
        return obj.alerts.count()


# Other serializers...
class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'


class DetectionRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionRule
        fields = '__all__'


class MLModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = MLModel
        fields = '__all__'


class HierarchicalModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = HierarchicalModel
        fields = '__all__'


class TrainingJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrainingJob
        fields = '__all__'


class NetworkInterfaceSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkInterface
        fields = '__all__'
