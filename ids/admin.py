# ids/admin.py
from django.contrib import admin
from .models import NetworkFlow


@admin.register(NetworkFlow)
class NetworkFlowAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'protocol', 'flow_duration', 'total_fwd_packets', 'prediction')
    list_filter = ('prediction', 'timestamp')
    search_fields = ('prediction',)
