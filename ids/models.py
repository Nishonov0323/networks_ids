# ids/models.py
from django.db import models


class NetworkFlow(models.Model):
    # Features from the dataset (same as test.csv)
    protocol = models.FloatField()
    flow_duration = models.FloatField()
    total_fwd_packets = models.FloatField()
    total_backward_packets = models.FloatField()
    fwd_packets_length_total = models.FloatField()
    bwd_packets_length_total = models.FloatField()
    fwd_packet_length_max = models.FloatField()
    fwd_packet_length_min = models.FloatField()
    fwd_packet_length_mean = models.FloatField()
    fwd_packet_length_std = models.FloatField()
    bwd_packet_length_max = models.FloatField()
    bwd_packet_length_min = models.FloatField()
    bwd_packet_length_mean = models.FloatField()
    bwd_packet_length_std = models.FloatField()
    flow_bytes_s = models.FloatField()
    flow_packets_s = models.FloatField()
    flow_iat_mean = models.FloatField()
    flow_iat_std = models.FloatField()
    flow_iat_max = models.FloatField()
    flow_iat_min = models.FloatField()
    fwd_iat_total = models.FloatField()
    fwd_iat_mean = models.FloatField()
    fwd_iat_std = models.FloatField()
    fwd_iat_max = models.FloatField()
    fwd_iat_min = models.FloatField()
    bwd_iat_total = models.FloatField()
    bwd_iat_mean = models.FloatField()
    bwd_iat_std = models.FloatField()
    bwd_iat_max = models.FloatField()
    bwd_iat_min = models.FloatField()
    fwd_psh_flags = models.FloatField()
    fwd_header_length = models.FloatField()
    bwd_header_length = models.FloatField()
    fwd_packets_s = models.FloatField()
    bwd_packets_s = models.FloatField()
    packet_length_min = models.FloatField()
    packet_length_max = models.FloatField()
    packet_length_mean = models.FloatField()
    packet_length_std = models.FloatField()
    packet_length_variance = models.FloatField()
    fin_flag_count = models.FloatField()
    syn_flag_count = models.FloatField()
    rst_flag_count = models.FloatField()
    psh_flag_count = models.FloatField()
    ack_flag_count = models.FloatField()
    urg_flag_count = models.FloatField()
    ece_flag_count = models.FloatField()
    down_up_ratio = models.FloatField()
    avg_packet_size = models.FloatField()
    avg_fwd_segment_size = models.FloatField()
    avg_bwd_segment_size = models.FloatField()
    subflow_fwd_packets = models.FloatField()
    subflow_fwd_bytes = models.FloatField()
    subflow_bwd_packets = models.FloatField()
    subflow_bwd_bytes = models.FloatField()
    init_fwd_win_bytes = models.FloatField()
    init_bwd_win_bytes = models.FloatField()
    fwd_act_data_packets = models.FloatField()
    fwd_seg_size_min = models.FloatField()
    active_mean = models.FloatField()
    active_std = models.FloatField()
    active_max = models.FloatField()
    active_min = models.FloatField()
    idle_mean = models.FloatField()
    idle_std = models.FloatField()
    idle_max = models.FloatField()
    idle_min = models.FloatField()

    # Prediction made by the ML model
    prediction = models.CharField(max_length=50, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Flow at {self.timestamp} - Prediction: {self.prediction}"


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Kam'),
        ('medium', 'O\'rta'),
        ('high', 'Yuqori'),
        ('critical', 'Kritik'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Ochiq'),
        ('acknowledged', 'Qabul qilingan'),
        ('resolved', 'Hal qilingan'),
        ('false_positive', 'Noto\'g\'ri signal'),
    ]
    
    title = models.CharField(max_length=200, verbose_name="Sarlavha")
    description = models.TextField(verbose_name="Tavsif")
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium', verbose_name="Jiddiylik darajasi")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open', verbose_name="Holat")
    network_flow = models.ForeignKey(NetworkFlow, on_delete=models.CASCADE, null=True, blank=True, verbose_name="Tarmoq oqimi")
    source_ip = models.GenericIPAddressField(null=True, blank=True, verbose_name="Manba IP")
    destination_ip = models.GenericIPAddressField(null=True, blank=True, verbose_name="Maqsad IP")
    attack_type = models.CharField(max_length=100, null=True, blank=True, verbose_name="Hujum turi")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Yaratilgan vaqt")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Yangilangan vaqt")
    acknowledged_at = models.DateTimeField(null=True, blank=True, verbose_name="Qabul qilingan vaqt")
    resolved_at = models.DateTimeField(null=True, blank=True, verbose_name="Hal qilingan vaqt")
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Ogohlantirish"
        verbose_name_plural = "Ogohlantirishlar"
    
    def __str__(self):
        return f"{self.title} - {self.get_severity_display()}"


class AlertRule(models.Model):
    name = models.CharField(max_length=200, verbose_name="Qoida nomi")
    description = models.TextField(verbose_name="Tavsif")
    attack_types = models.JSONField(default=list, verbose_name="Hujum turlari")  # List of attack types to trigger on
    min_severity_score = models.FloatField(default=0.7, verbose_name="Minimal jiddiylik bahosi")
    is_active = models.BooleanField(default=True, verbose_name="Faol")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Yaratilgan vaqt")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Yangilangan vaqt")
    
    class Meta:
        verbose_name = "Ogohlantirish qoidasi"
        verbose_name_plural = "Ogohlantirish qoidalari"
    
    def __str__(self):
        return self.name
