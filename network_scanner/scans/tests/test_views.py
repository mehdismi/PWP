"""Integration tests for the scan API including create, list, retrieve, delete, run, and cancel operations."""

import pytest
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from scans.models import Scan

User = get_user_model()


@pytest.mark.django_db
def test_create_scan():
    """Test creating a new scan."""
    user = User.objects.create_user(username='scanuser', password='Scan123')
    client = APIClient()
    client.force_authenticate(user=user)

    payload = {
        "name": "Test Scan",
        "description": "Testing scan create",
        "target": "127.0.0.1",
        "scan_type": "host_discovery"
    }

    response = client.post('/api/v1/scans/', payload)

    assert response.status_code == 201
    assert response.data['name'] == "Test Scan"
    assert response.data['scan_type'] == "host_discovery"


@pytest.mark.django_db
def test_list_scans():
    """Test listing scans for a user."""
    user = User.objects.create_user(username='scanlist', password='Test123')
    Scan.objects.create(name='Scan A', user=user, target='127.0.0.1', scan_type='host_discovery')
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.get('/api/v1/scans/')

    assert response.status_code == 200
    assert len(response.data) >= 1


@pytest.mark.django_db
def test_retrieve_scan_detail():
    """Test retrieving scan details."""
    user = User.objects.create_user(username='scanview', password='Test123')
    scan = Scan.objects.create(name='Detail Scan', user=user, target='127.0.0.1', scan_type='open_ports')
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.get(f'/api/v1/scans/{scan.id}/')

    assert response.status_code == 200
    assert response.data['name'] == 'Detail Scan'


@pytest.mark.django_db
def test_delete_scan():
    """Test deleting a scan."""
    user = User.objects.create_user(username='scandelete', password='Test123')
    scan = Scan.objects.create(name='To be deleted', user=user, target='127.0.0.1', scan_type='os_services')
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.delete(f'/api/v1/scans/{scan.id}/')

    assert response.status_code == 204
    assert not Scan.objects.filter(id=scan.id).exists()


@pytest.mark.django_db
def test_run_scan_invalid_type():
    """Test attempting to run a scan with an invalid scan type."""
    user = User.objects.create_user(username='scanrunner', password='Test123')
    scan = Scan.objects.create(name='Bad scan', user=user, target='127.0.0.1', scan_type='invalid_type')
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.post(f'/api/v1/scans/{scan.id}/run/')

    assert response.status_code == 400
    assert "Invalid scan type" in response.data["error"]


@pytest.mark.django_db
def test_cancel_scan_not_running():
    """Test attempting to cancel a scan that is not running."""
    user = User.objects.create_user(username='scanstopper', password='Test123')
    scan = Scan.objects.create(name='Cancel scan', user=user, target='127.0.0.1', scan_type='host_discovery', status='pending')
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.post(f'/api/v1/scans/{scan.id}/cancel/')

    assert response.status_code == 400
    assert "Scan is not running" in response.data["error"]
