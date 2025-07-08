# ids/admin.py
from django.contrib import admin
from .models import NetworkFlow, Alert, AlertRule


@admin.register(NetworkFlow)
class NetworkFlowAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'protocol', 'flow_duration', 'total_fwd_packets', 'prediction')
    list_filter = ('prediction', 'timestamp')
    search_fields = ('prediction',)


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'status', 'attack_type', 'created_at')
    list_filter = ('severity', 'status', 'attack_type', 'created_at')
    search_fields = ('title', 'description', 'attack_type')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('title', 'description', 'severity', 'status')
        }),
        ('Attack Details', {
            'fields': ('attack_type', 'source_ip', 'destination_ip', 'network_flow')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'acknowledged_at', 'resolved_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(AlertRule)
class AlertRuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_active', 'min_severity_score', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'description')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Rule Configuration', {
            'fields': ('name', 'description', 'is_active')
        }),
        ('Detection Settings', {
            'fields': ('attack_types', 'min_severity_score')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
