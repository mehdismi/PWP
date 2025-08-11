# pylint: disable=line-too-long
# pylint: disable=no-member
# pylint: disable=too-many-ancestors
# pylint: disable=broad-exception-caught
# pylint: disable=unused-argument
"""Views for managing scans, including execution, cancellation, and dashboard summary."""
import time
import os
import re
import signal
import subprocess
import xmltodict

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from accounts.models import ActivityLog
from rest_framework import filters
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

from .models import Scan
from .serializers import ScanSerializer


class ScanViewSet(viewsets.ModelViewSet):
    """ViewSet for managing scans."""
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['name']

    def get_queryset(self):
        """Return only scans owned by the requesting user."""
        return self.queryset.filter(user=self.request.user)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a running scan using its PID."""
        scan = self.get_object()

        if scan.status != 'running':
            return Response({"error": "Scan is not running."}, status=status.HTTP_400_BAD_REQUEST)

        if not scan.pid:
            return Response({"error": "No PID found for this scan."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            os.kill(scan.pid, signal.SIGKILL) # linux
            #os.kill(scan.pid, signal.SIGTERM) # windows
            scan.status = 'cancelled'
            scan.progress = 0
            scan.pid = None
            scan.save()
            return Response({"message": "Scan cancelled successfully."})
        except Exception as e:
            return Response({"error": "Failed to cancel scan.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



    @action(detail=True, methods=['post'])
    def run(self, request, pk=None):
        """Execute a scan based on the selected type and target."""
        scan = self.get_object()
        scan.status = "running"
        scan.progress = 0
        scan.save()

        try:
            if scan.scan_type == 'host_discovery':
                cmd = ["nmap", scan.target, "-sn", "--stats-every", "5s", "-oX", "result.xml"]
            elif scan.scan_type == 'open_ports':
                cmd = ["nmap", scan.target, "--open", "--stats-every", "5s", "-oX", "result.xml"]
            elif scan.scan_type == 'os_services':
                cmd = ["nmap", scan.target, "-A", "--stats-every", "5s", "-oX", "result.xml"]
            else:
                return Response({"error": "Invalid scan type"}, status=status.HTTP_400_BAD_REQUEST)

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            scan.pid = process.pid
            scan.save()

            for line in process.stdout:
                match = re.search(r'About (\d+)% done', line)
                if match:
                    percentage = int(match.group(1))
                    scan.progress = percentage
                    scan.save()

            process.wait()

            with open("result.xml", encoding="utf-8") as f:
                xml_data = f.read()
            json_data = xmltodict.parse(xml_data)

            scan.result = json_data
            scan.status = "completed"
            scan.progress = 100
            scan.save()

            return Response({"message": "Scan completed successfully.", "result": json_data})

        except Exception as e:
            scan.status = "failed"
            scan.save()
            return Response({"error": "Scan failed", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




    def perform_create(self, serializer):
        scan = serializer.save(user=self.request.user)
        ActivityLog.objects.create(user=self.request.user, action=f"Created scan: {scan.name}")

    def perform_destroy(self, instance):
        """Log scan deletion."""
        ActivityLog.objects.create(user=self.request.user, action=f"Deleted scan: {instance.name}")
        instance.delete()


class DashboardSummaryView(APIView):
    """Return a summary of all scans for the authenticated user."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        scans = Scan.objects.filter(user=user)

        summary = {
            "running_scans": scans.filter(status='running').count(),
            "scans": []
        }

        for scan in scans:
            result = scan.result or {}
            open_ports = []
            services = []
            up_hosts = 0

            try:
                up_hosts = int(result.get('nmaprun', {}).get('runstats', {}).get('hosts', {}).get('@up', 0))
            except:
                up_hosts = 0

            try:
                hosts = result.get('nmaprun', {}).get('host', [])
                if isinstance(hosts, dict):
                    hosts = [hosts]

                for host in hosts:
                    ports = host.get('ports', {}).get('port', [])
                    if isinstance(ports, dict):
                        ports = [ports]

                    for port in ports:
                        if port.get('state', {}).get('@state') == 'open':
                            port_id = port.get('@portid')
                            open_ports.append(port_id)
                            service_name = port.get('service', {}).get('@name')
                            if service_name:
                                services.append(service_name)

            except:
                pass

            summary["scans"].append({
                "scan_id": scan.id,
                "scan_name": scan.name,
                "open_ports_count": len(open_ports),
                "open_ports_list": open_ports,
                "services_list": services,
                "up_hosts": up_hosts
            })

        return Response(summary)
