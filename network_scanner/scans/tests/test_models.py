import pytest
from django.contrib.auth import get_user_model
from scans.models import Scan

@pytest.mark.django_db
def test_scan_defaults_and_str():
    User = get_user_model()
    u = User.objects.create_user(username="u1", password="p")
    s = Scan.objects.create(
        user=u, name="S1", target="127.0.0.1", scan_type="open_ports"
    )
    assert s.status == "pending"
    assert s.progress == 0
    assert s.pid is None
    assert str(s) == f"S1 ({u.username})"
