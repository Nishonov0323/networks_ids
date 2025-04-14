# ids/management/commands/setup_rules.py
from django.core.management.base import BaseCommand
from ids.models import DetectionRule
import json


class Command(BaseCommand):
    help = 'Set up initial detection rules for the IDS'

    def handle(self, *args, **kwargs):
        # Rule 1: High Packet Rate (DoS)
        DetectionRule.objects.get_or_create(
            name="High Packet Rate (DoS)",
            defaults={
                'description': 'Detects potential DoS attacks based on high packet rate',
                'rule_type': 'SIGNATURE',
                'rule_details': json.dumps({'packet_rate_threshold': 100}),
                'severity': 4,
                'enabled': True
            }
        )

        # Rule 2: Port Scan Detection
        DetectionRule.objects.get_or_create(
            name="Port Scan Detection",
            defaults={
                'description': 'Detects port scanning activity',
                'rule_type': 'SIGNATURE',
                'rule_details': json.dumps({'port_threshold': 10}),
                'severity': 3,
                'enabled': True
            }
        )

        self.stdout.write(self.style.SUCCESS('Successfully set up detection rules'))
