# pylint: disable=no-member
# pylint: disable=line-too-long

"""Models for the scan application, including scan metadata and results."""
from django.db import models
from django.conf import settings

class Scan(models.Model):
    """Model representing a network scan requested by a user."""
    SCAN_TYPE_CHOICES = [
        ('host_discovery', 'Host Discovery'),
        ('open_ports', 'Open Ports'),
        ('os_services', 'OS, Services, and Version Detection'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='scans')

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    target = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=50, choices=SCAN_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    result = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    progress = models.IntegerField(default=0)
    pid = models.IntegerField(null=True, blank=True)

    def __str__(self):
        """Return human-readable representation of a scan."""
        return f"{self.name} ({self.user.username})"
    