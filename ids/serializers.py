# serializers.py
from rest_framework import serializers
from .models import (
    NetworkFlow, Alert, DetectionRule, MLModel,
    HierarchicalModel, TrainingJob, NetworkInterface
)


class NetworkFlowSerializer(serializers.ModelSerializer):
    """Serializer for NetworkFlow model"""
    alert_count = serializers.SerializerMethodField()

    class Meta:
        model = NetworkFlow
        fields = '__all__'

    def get_alert_count(self, obj):
        """Get the number of alerts associated with this flow"""
        return obj.alerts.count()


class DetectionRuleSerializer(serializers.ModelSerializer):
    """Serializer for DetectionRule model"""
    rule_details_dict = serializers.SerializerMethodField()

    class Meta:
        model = DetectionRule
        fields = '__all__'

    def get_rule_details_dict(self, obj):
        """Get rule details as a dictionary"""
        return obj.get_rule_details()


class AlertSerializer(serializers.ModelSerializer):
    """Serializer for Alert model"""
    rule_name = serializers.SerializerMethodField()
    flow_info = serializers.SerializerMethodField()

    class Meta:
        model = Alert
        fields = '__all__'

    def get_rule_name(self, obj):
        """Get the name of the rule that triggered this alert"""
        return obj.rule.name if obj.rule else "Unknown"

    def get_flow_info(self, obj):
        """Get basic flow information for this alert"""
        flow = obj.flow
        return {
            'source_ip': flow.source_ip,
            'destination_ip': flow.destination_ip,
            'source_port': flow.source_port,
            'destination_port': flow.destination_port,
            'protocol': flow.protocol
        }


class MLModelSerializer(serializers.ModelSerializer):
    """Serializer for MLModel model"""
    parameters_dict = serializers.SerializerMethodField()

    class Meta:
        model = MLModel
        fields = '__all__'

    def get_parameters_dict(self, obj):
        """Get model parameters as a dictionary"""
        return obj.get_parameters()


class TrainingJobSerializer(serializers.ModelSerializer):
    """Serializer for TrainingJob model"""
    model_name = serializers.SerializerMethodField()
    dataset_info_dict = serializers.SerializerMethodField()
    training_parameters_dict = serializers.SerializerMethodField()
    results_dict = serializers.SerializerMethodField()

    class Meta:
        model = TrainingJob
        fields = '__all__'

    def get_model_name(self, obj):
        """Get the name of the model being trained"""
        return obj.model.name

    def get_dataset_info_dict(self, obj):
        """Get dataset info as a dictionary"""
        return obj.get_dataset_info()

    def get_training_parameters_dict(self, obj):
        """Get training parameters as a dictionary"""
        return obj.get_training_parameters()

    def get_results_dict(self, obj):
        """Get results as a dictionary"""
        return obj.get_results()


class HierarchicalModelSerializer(serializers.ModelSerializer):
    """Serializer for HierarchicalModel model"""
    structure_dict = serializers.SerializerMethodField()
    model_names = serializers.SerializerMethodField()

    class Meta:
        model = HierarchicalModel
        fields = '__all__'

    def get_structure_dict(self, obj):
        """Get hierarchical structure as a dictionary"""
        return obj.get_structure()

    def get_model_names(self, obj):
        """Get the names of models used in this hierarchical model"""
        return [model.name for model in obj.modelss.all()]


class NetworkInterfaceSerializer(serializers.ModelSerializer):
    """Serializer for NetworkInterface model"""

    class Meta:
        model = NetworkInterface
        fields = '__all__'