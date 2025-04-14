# admin.py
from django.contrib import admin
from .models import (
    NetworkFlow, Alert, DetectionRule, MLModel,
    HierarchicalModel, TrainingJob, NetworkInterface,
)


class NetworkFlowAdmin(admin.ModelAdmin):
    list_display = ('source_ip', 'destination_ip', 'protocol', 'timestamp', 'packet_count', 'byte_count')
    list_filter = ('protocol', 'timestamp')
    search_fields = ('source_ip', 'destination_ip')
    date_hierarchy = 'timestamp'


class AlertAdmin(admin.ModelAdmin):
    list_display = ('rule', 'status', 'timestamp', 'confidence', 'attack_category')
    list_filter = ('status', 'attack_category', 'timestamp')
    search_fields = ('rule__name', 'attack_subcategory', 'details')
    date_hierarchy = 'timestamp'


class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'rule_type', 'severity', 'enabled')
    list_filter = ('rule_type', 'severity', 'enabled')
    search_fields = ('name', 'description')


class MLModelAdmin(admin.ModelAdmin):
    list_display = ('name', 'model_type', 'accuracy', 'created_at')
    list_filter = ('model_type', 'created_at')
    search_fields = ('name', 'description')


class HierarchicalModelAdmin(admin.ModelAdmin):
    list_display = ('name', 'enabled', 'created_at')
    list_filter = ('enabled', 'created_at')
    search_fields = ('name', 'description')


class TrainingJobAdmin(admin.ModelAdmin):
    list_display = ('model', 'status', 'start_time', 'end_time')
    list_filter = ('status', 'start_time')
    search_fields = ('model__name',)


class NetworkInterfaceAdmin(admin.ModelAdmin):
    list_display = ('name', 'interface_type', 'ip_address', 'is_monitoring')
    list_filter = ('interface_type', 'is_monitoring')
    search_fields = ('name', 'ip_address', 'mac_address')


# Register models with admin site
admin.site.register(NetworkFlow, NetworkFlowAdmin)
admin.site.register(Alert, AlertAdmin)
admin.site.register(DetectionRule, DetectionRuleAdmin)
admin.site.register(MLModel, MLModelAdmin)
admin.site.register(HierarchicalModel, HierarchicalModelAdmin)
admin.site.register(TrainingJob, TrainingJobAdmin)
admin.site.register(NetworkInterface, NetworkInterfaceAdmin)
