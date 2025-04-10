# views.py
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, action
from rest_framework.response import Response
from django.shortcuts import render
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
import json

from .models import (
    NetworkFlow, Alert, DetectionRule, MLModel,
    HierarchicalModel, TrainingJob, NetworkInterface
)
from .services import PacketProcessor, DetectionService
from .serializers import (
    NetworkFlowSerializer, AlertSerializer, DetectionRuleSerializer,
    MLModelSerializer, HierarchicalModelSerializer, TrainingJobSerializer,
    NetworkInterfaceSerializer
)


# Main dashboard view
def dashboard(request):
    """Main dashboard view for the IDS"""
    # Get statistics for display
    total_flows = NetworkFlow.objects.count()
    total_alerts = Alert.objects.count()

    # Get alerts from the last 24 hours
    one_day_ago = timezone.now() - timedelta(days=1)
    recent_alerts = Alert.objects.filter(timestamp__gte=one_day_ago).count()

    # Get category distribution
    categories = Alert.objects.values('attack_category').annotate(
        count=Count('id')
    ).order_by('-count')

    # Get active interfaces
    active_interfaces = NetworkInterface.objects.filter(is_monitoring=True).count()

    context = {
        'total_flows': total_flows,
        'total_alerts': total_alerts,
        'recent_alerts': recent_alerts,
        'categories': categories,
        'active_interfaces': active_interfaces,
    }

    return render(request, 'ids/dashboard.html', context)


# API Views using DRF ViewSets
# views.py (continued)
class NetworkFlowViewSet(viewsets.ModelViewSet):
    """ViewSet for NetworkFlow model"""
    queryset = NetworkFlow.objects.all().order_by('-timestamp')
    serializer_class = NetworkFlowSerializer

    def get_queryset(self):
        """Filter queryset based on query parameters"""
        queryset = NetworkFlow.objects.all().order_by('-timestamp')

        # Apply filters if provided
        source_ip = self.request.query_params.get('source_ip', None)
        if source_ip:
            queryset = queryset.filter(source_ip=source_ip)

        destination_ip = self.request.query_params.get('destination_ip', None)
        if destination_ip:
            queryset = queryset.filter(destination_ip=destination_ip)

        protocol = self.request.query_params.get('protocol', None)
        if protocol:
            queryset = queryset.filter(protocol=protocol)

        # Time range filter
        start_time = self.request.query_params.get('start_time', None)
        if start_time:
            queryset = queryset.filter(timestamp__gte=start_time)

        end_time = self.request.query_params.get('end_time', None)
        if end_time:
            queryset = queryset.filter(timestamp__lte=end_time)

        return queryset


class AlertViewSet(viewsets.ModelViewSet):
    """ViewSet for Alert model"""
    queryset = Alert.objects.all().order_by('-timestamp')
    serializer_class = AlertSerializer

    def get_queryset(self):
        """Filter queryset based on query parameters"""
        queryset = Alert.objects.all().order_by('-timestamp')

        # Apply filters if provided
        status = self.request.query_params.get('status', None)
        if status:
            queryset = queryset.filter(status=status)

        category = self.request.query_params.get('attack_category', None)
        if category:
            queryset = queryset.filter(attack_category=category)

        # Filter by confidence threshold
        min_confidence = self.request.query_params.get('min_confidence', None)
        if min_confidence:
            queryset = queryset.filter(confidence__gte=float(min_confidence))

        # Time range filter
        start_time = self.request.query_params.get('start_time', None)
        if start_time:
            queryset = queryset.filter(timestamp__gte=start_time)

        end_time = self.request.query_params.get('end_time', None)
        if end_time:
            queryset = queryset.filter(timestamp__lte=end_time)

        # Filter by related flow
        flow_id = self.request.query_params.get('flow_id', None)
        if flow_id:
            queryset = queryset.filter(flow_id=flow_id)

        return queryset

    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        """API endpoint to update alert status"""
        alert = self.get_object()
        status = request.data.get('status')

        if status not in [choice[0] for choice in Alert.STATUS_CHOICES]:
            return Response(
                {'error': 'Invalid status value'},
                status=status.HTTP_400_BAD_REQUEST
            )

        alert.status = status
        alert.save()

        return Response({'status': 'Alert status updated'})


class DetectionRuleViewSet(viewsets.ModelViewSet):
    """ViewSet for DetectionRule model"""
    queryset = DetectionRule.objects.all().order_by('name')
    serializer_class = DetectionRuleSerializer

    def get_queryset(self):
        """Filter queryset based on query parameters"""
        queryset = DetectionRule.objects.all().order_by('name')

        # Apply filters if provided
        rule_type = self.request.query_params.get('rule_type', None)
        if rule_type:
            queryset = queryset.filter(rule_type=rule_type)

        enabled = self.request.query_params.get('enabled', None)
        if enabled is not None:
            queryset = queryset.filter(enabled=(enabled.lower() == 'true'))

        # Filter by severity level
        min_severity = self.request.query_params.get('min_severity', None)
        if min_severity:
            queryset = queryset.filter(severity__gte=int(min_severity))

        return queryset

    @action(detail=True, methods=['post'])
    def toggle_enabled(self, request, pk=None):
        """API endpoint to toggle rule enabled status"""
        rule = self.get_object()
        rule.enabled = not rule.enabled
        rule.save()

        return Response({'enabled': rule.enabled})


class MLModelViewSet(viewsets.ModelViewSet):
    """ViewSet for MLModel model"""
    queryset = MLModel.objects.all().order_by('name')
    serializer_class = MLModelSerializer

    def get_queryset(self):
        """Filter queryset based on query parameters"""
        queryset = MLModel.objects.all().order_by('name')

        # Apply filters if provided
        model_type = self.request.query_params.get('model_type', None)
        if model_type:
            queryset = queryset.filter(model_type=model_type)

        # Filter by performance metrics
        min_accuracy = self.request.query_params.get('min_accuracy', None)
        if min_accuracy:
            queryset = queryset.filter(accuracy__gte=float(min_accuracy))

        return queryset

    @action(detail=True, methods=['post'])
    def start_training(self, request, pk=None):
        """API endpoint to start model training"""
        ml_model = self.get_object()

        # Create a new training job
        training_job = TrainingJob(
            model=ml_model,
            status='PENDING',
            dataset_info=json.dumps(request.data.get('dataset_info', {})),
            training_parameters=json.dumps(request.data.get('training_parameters', {}))
        )
        training_job.save()

        # In a real implementation, you would start a background task
        # to handle the actual training process

        return Response({
            'job_id': training_job.id,
            'status': 'Training job created'
        })


class HierarchicalModelViewSet(viewsets.ModelViewSet):
    """ViewSet for HierarchicalModel model"""
    queryset = HierarchicalModel.objects.all().order_by('name')
    serializer_class = HierarchicalModelSerializer

    @action(detail=True, methods=['post'])
    def toggle_enabled(self, request, pk=None):
        """API endpoint to toggle hierarchical model enabled status"""
        model = self.get_object()
        model.enabled = not model.enabled
        model.save()

        return Response({'enabled': model.enabled})


class TrainingJobViewSet(viewsets.ModelViewSet):
    """ViewSet for TrainingJob model"""
    queryset = TrainingJob.objects.all().order_by('-start_time')
    serializer_class = TrainingJobSerializer

    def get_queryset(self):
        """Filter queryset based on query parameters"""
        queryset = TrainingJob.objects.all().order_by('-start_time')

        # Apply filters if provided
        status = self.request.query_params.get('status', None)
        if status:
            queryset = queryset.filter(status=status)

        # Filter by model
        model_id = self.request.query_params.get('model_id', None)
        if model_id:
            queryset = queryset.filter(model_id=model_id)

        return queryset


class NetworkInterfaceViewSet(viewsets.ModelViewSet):
    """ViewSet for NetworkInterface model"""
    queryset = NetworkInterface.objects.all().order_by('name')
    serializer_class = NetworkInterfaceSerializer

    @action(detail=True, methods=['post'])
    def toggle_monitoring(self, request, pk=None):
        """API endpoint to toggle network interface monitoring status"""
        interface = self.get_object()
        interface.is_monitoring = not interface.is_monitoring
        interface.save()

        # In a real implementation, you would start/stop a packet capture
        # process for this interface

        return Response({'is_monitoring': interface.is_monitoring})


# API view for packet ingestion
@api_view(['POST'])
def ingest_packet(request):
    """API endpoint to ingest a network packet"""
    packet_data = request.data

    # Initialize the packet processor
    processor = PacketProcessor()

    # Process the packet
    flow_key = processor.process_packet(packet_data)

    if flow_key:
        return Response({'status': 'Packet processed', 'flow_key': flow_key})
    else:
        return Response(
            {'error': 'Failed to process packet'},
            status=status.HTTP_400_BAD_REQUEST
        )


# API view for statistics
@api_view(['GET'])
def get_statistics(request):
    """API endpoint to get IDS statistics"""
    # Time range for statistics
    days = int(request.query_params.get('days', 7))
    start_date = timezone.now() - timedelta(days=days)

    # Get flow statistics
    total_flows = NetworkFlow.objects.count()
    recent_flows = NetworkFlow.objects.filter(timestamp__gte=start_date).count()

    # Get alert statistics
    total_alerts = Alert.objects.count()
    recent_alerts = Alert.objects.filter(timestamp__gte=start_date).count()

    # Get alerts by category
    alerts_by_category = Alert.objects.filter(
        timestamp__gte=start_date
    ).values('attack_category').annotate(
        count=Count('id')
    ).order_by('-count')

    # Get alerts by status
    alerts_by_status = Alert.objects.filter(
        timestamp__gte=start_date
    ).values('status').annotate(
        count=Count('id')
    ).order_by('-count')

    # Get alerts by confidence range
    alerts_by_confidence = {
        'high': Alert.objects.filter(confidence__gte=0.8, timestamp__gte=start_date).count(),
        'medium': Alert.objects.filter(confidence__gte=0.5, confidence__lt=0.8, timestamp__gte=start_date).count(),
        'low': Alert.objects.filter(confidence__lt=0.5, timestamp__gte=start_date).count(),
    }

    # Get top source IPs in alerts
    top_source_ips = NetworkFlow.objects.filter(
        alerts__isnull=False,
        timestamp__gte=start_date
    ).values('source_ip').annotate(
        alert_count=Count('alerts')
    ).order_by('-alert_count')[:10]

    statistics = {
        'total_flows': total_flows,
        'recent_flows': recent_flows,
        'total_alerts': total_alerts,
        'recent_alerts': recent_alerts,
        'alerts_by_category': list(alerts_by_category),
        'alerts_by_status': list(alerts_by_status),
        'alerts_by_confidence': alerts_by_confidence,
        'top_source_ips': list(top_source_ips),
    }

    return Response(statistics)

def settings_page(request):
    return render(request, 'ids/settings.html')

def flows_page(request):
    return render(request, 'ids/flows.html')

def alerts_page(request):
    return render(request, 'ids/alerts.html')

@api_view(['GET'])
def statistics(request):
    # Categories
    categories = Alert.objects.values('attack_category').annotate(count=models.Count('id'))

    # Timeline (last 24 hours)
    last_24h = timezone.now() - timedelta(hours=24)
    timeline = Alert.objects.filter(timestamp__gte=last_24h)\
        .extra({'hour': "strftime('%%Y-%%m-%%d %%H', timestamp)"})\
        .values('hour')\
        .annotate(count=models.Count('id'))\
        .order_by('hour')

    return Response({
        'categories': list(categories),
        'timeline': list(timeline),
    })
