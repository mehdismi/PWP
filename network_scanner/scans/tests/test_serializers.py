import pytest
from django.contrib.auth import get_user_model
from scans.serializers import ScanSerializer
from scans.models import Scan

@pytest.mark.django_db
def test_scan_serializer_create_enforces_readonly_fields():
    User = get_user_model()
    u = User.objects.create_user(username="u2", password="p")

    data = {
        "name": "S2",
        "description": "desc",
        "target": "localhost",
        "scan_type": "host_discovery",
        "status": "completed", 
        "user": u.id,
    }
    ser = ScanSerializer(data=data)
    assert ser.is_valid(), ser.errors

@pytest.mark.django_db
def test_scan_serializer_required_fields_validation():
    ser = ScanSerializer(data={"name": "S3"})
    assert not ser.is_valid()
    assert "target" in ser.errors
    assert "scan_type" in ser.errors
