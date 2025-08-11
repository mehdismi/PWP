"""Serializers for the Scan model, used in the scan API."""
from rest_framework import serializers
from .models import Scan

class ScanSerializer(serializers.ModelSerializer): # pylint: disable=too-few-public-methods
    """Serializer for creating, reading, and updating Scan instances."""
    class Meta: # pylint: disable=too-few-public-methods
        model = Scan
        fields = '__all__'
        read_only_fields = ('user', 'status', 'result', 'created_at', 'updated_at')
