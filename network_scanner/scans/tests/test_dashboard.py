import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from scans.models import Scan

@pytest.mark.django_db
def test_dashboard_summary_counts_open_ports_and_up_hosts():
    U = get_user_model()
    user = U.objects.create_user("u3", password="p")
    client = APIClient()
    client.force_authenticate(user=user)

    res1 = {
        "nmaprun": {
            "runstats": {"hosts": {"@up": "1"}},
            "host": {
                "ports": {"port": {
                    "@portid": "22",
                    "state": {"@state": "open"},
                    "service": {"@name": "ssh"}
                }}
            }
        }
    }
    res2 = {
        "nmaprun": {
            "runstats": {"hosts": {"@up": "0"}},
            "host": [
                {"ports": {"port": [
                    {"@portid": "80", "state": {"@state": "open"}, "service": {"@name": "http"}},
                    {"@portid": "443", "state": {"@state": "closed"}}
                ]}}
            ]
        }
    }

    Scan.objects.create(user=user, name="A", target="t", scan_type="open_ports", status="completed", result=res1)
    Scan.objects.create(user=user, name="B", target="t", scan_type="open_ports", status="completed", result=res2)

    resp = client.get(reverse("dashboard-summary"))
    assert resp.status_code == 200
    data = resp.data
    assert data["running_scans"] == 0
    found = {s["scan_name"]: s for s in data["scans"]}
    assert found["A"]["open_ports_count"] == 1
    assert found["A"]["up_hosts"] == 1
    assert "22" in found["A"]["open_ports_list"]
    assert "ssh" in found["A"]["services_list"]

    assert found["B"]["open_ports_count"] == 1
    assert found["B"]["up_hosts"] == 0
    assert "80" in found["B"]["open_ports_list"]
    assert "http" in found["B"]["services_list"]
