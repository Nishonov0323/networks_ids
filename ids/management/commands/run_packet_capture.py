# management/commands/run_packet_capture.py
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.utils import timezone
import time
import signal
import sys

from ids.packet_capture import InterfaceManager
from ids.models import NetworkInterface


class Command(BaseCommand):
    help = 'Run the network packet capture service'

    def add_arguments(self, parser):
        parser.add_argument(
            'action',
            choices=['start', 'stop', 'status'],
            help='Action to perform (start, stop, or status)'
        )
        parser.add_argument(
            '--interface',
            help='Network interface to capture packets from (default: all enabled interfaces)'
        )
        parser.add_argument(
            '--api-url',
            help='API URL for the IDS packet ingestion endpoint'
        )

    def handle(self, *args, **options):
        action = options['action']
        interface_name = options['interface']
        api_url = options['api_url'] or 'http://localhost:8000/api/ingest/'

        # Create the interface manager
        manager = InterfaceManager(api_url)

        if action == 'start':
            self._start_capture(manager, interface_name)
        elif action == 'stop':
            self._stop_capture(manager, interface_name)
        elif action == 'status':
            self._show_status(manager)

    def _start_capture(self, manager, interface_name):
        """Start packet capture on specified interfaces"""
        if interface_name:
            # Start capture on specified interface
            try:
                interface = NetworkInterface.objects.get(name=interface_name)

                if manager.start_interface(interface_name):
                    interface.is_monitoring = True
                    interface.save()
                    self.stdout.write(self.style.SUCCESS(f"Started packet capture on {interface_name}"))
                else:
                    self.stdout.write(self.style.ERROR(f"Failed to start packet capture on {interface_name}"))

            except NetworkInterface.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"Interface {interface_name} not found in database"))
                return

        else:
            # Start capture on all enabled interfaces
            interfaces = NetworkInterface.objects.filter(is_monitoring=False)

            if not interfaces:
                self.stdout.write(self.style.WARNING("No inactive interfaces found"))
                return

            for interface in interfaces:
                if manager.start_interface(interface.name):
                    interface.is_monitoring = True
                    interface.save()
                    self.stdout.write(self.style.SUCCESS(f"Started packet capture on {interface.name}"))
                else:
                    self.stdout.write(self.style.ERROR(f"Failed to start packet capture on {interface.name}"))

        # Run until interrupted
        self.stdout.write("Press Ctrl+C to stop packet capture")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self._stop_capture(manager, interface_name)

    def _stop_capture(self, manager, interface_name):
        """Stop packet capture on specified interfaces"""
        if interface_name:
            # Stop capture on specified interface
            try:
                interface = NetworkInterface.objects.get(name=interface_name)

                if manager.stop_interface(interface_name):
                    interface.is_monitoring = False
                    interface.save()
                    self.stdout.write(self.style.SUCCESS(f"Stopped packet capture on {interface_name}"))
                else:
                    self.stdout.write(self.style.ERROR(f"Failed to stop packet capture on {interface_name}"))

            except NetworkInterface.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"Interface {interface_name} not found in database"))
                return

        else:
            # Stop capture on all active interfaces
            interfaces = NetworkInterface.objects.filter(is_monitoring=True)

            if not interfaces:
                self.stdout.write(self.style.WARNING("No active interfaces found"))
                return

            for interface in interfaces:
                if manager.stop_interface(interface.name):
                    interface.is_monitoring = False
                    interface.save()
                    self.stdout.write(self.style.SUCCESS(f"Stopped packet capture on {interface.name}"))
                else:
                    self.stdout.write(self.style.ERROR(f"Failed to stop packet capture on {interface.name}"))

        def _show_status(self, manager):
            """Show status of all interfaces"""
            interfaces = NetworkInterface.objects.all()

            if not interfaces:
                self.stdout.write(self.style.WARNING("No interfaces found in database"))
                return

            self.stdout.write(self.style.SUCCESS("Interface Status:"))
            self.stdout.write("-" * 50)
            self.stdout.write(f"{'Name':<15} {'Type':<10} {'IP Address':<15} {'Status':<10}")
            self.stdout.write("-" * 50)

            active_interfaces = manager.get_active_interfaces()

            for interface in interfaces:
                status = "ACTIVE" if interface.name in active_interfaces or interface.is_monitoring else "INACTIVE"
                self.stdout.write(
                    f"{interface.name:<15} {interface.interface_type:<10} {interface.ip_address or 'N/A':<15} {status:<10}"
                )
