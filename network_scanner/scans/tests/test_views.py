import io
import builtins
import pytest
from unittest.mock import patch, MagicMock
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from scans.models import Scan

@pytest.fixture
def client():
    return APIClient()

@pytest.fixture
def users(db):
    U = get_user_model()
    return U.objects.create_user("me", password="p"), U.objects.create_user("other", password="p")

@pytest.fixture
def auth_client(client, users):
    me, _ = users
    client.force_authenticate(user=me)
    return client

@pytest.mark.django_db
def test_list_returns_only_own_scans(auth_client, users):
    me, other = users
    Scan.objects.create(user=me, name="Mine", target="127.0.0.1", scan_type="open_ports")
    Scan.objects.create(user=other, name="NotMine", target="127.0.0.1", scan_type="open_ports")

    url = reverse("scan-list")
    resp = auth_client.get(url)
    assert resp.status_code == 200
    names = [s["name"] for s in resp.data]
    assert names == ["Mine"]

@pytest.mark.django_db
def test_create_sets_user_and_logs_activity(auth_client, users):
    me, _ = users
    url = reverse("scan-list")
    data = {"name": "S1", "target": "127.0.0.1", "scan_type": "host_discovery"}

    with patch("scans.views.ActivityLog.objects.create") as mlog:
        resp = auth_client.post(url, data, format="json")
    assert resp.status_code == 201
    obj = Scan.objects.get(name="S1")
    assert obj.user == me
    mlog.assert_called_once()

@pytest.mark.django_db
def test_search_filter(auth_client, users):
    me, _ = users
    Scan.objects.create(user=me, name="WebSrv", target="1.1.1.1", scan_type="open_ports")
    Scan.objects.create(user=me, name="DBSrv", target="2.2.2.2", scan_type="open_ports")

    url = reverse("scan-list") + "?search=Web"
    resp = auth_client.get(url)
    assert resp.status_code == 200
    assert len(resp.data) == 1 and resp.data[0]["name"] == "WebSrv"

@pytest.mark.django_db
def test_run_success_flow(auth_client, users, tmp_path, monkeypatch):
    me, _ = users
    s = Scan.objects.create(user=me, name="R1", target="127.0.0.1", scan_type="open_ports")

    class FakePopen:
        def __init__(self, *args, **kwargs):
            self.pid = 12345
            self.stdout = io.StringIO("About 5% done\nAbout 25% done\n")
        def wait(self): return 0

    monkeypatch.setenv("PYTHONUNBUFFERED", "1")
    with patch("scans.views.subprocess.Popen", return_value=FakePopen()):
        xml_text = """<nmaprun>
            <runstats><hosts up="1"/></runstats>
            <host><ports>
              <port portid="22"><state state="open"/><service name="ssh"/></port>
            </ports></host>
        </nmaprun>"""
        m_open = patch.object(builtins, "open", MagicMock())
        with patch("builtins.open", MagicMock(return_value=io.StringIO(xml_text))):
            url = reverse("scan-run", kwargs={"pk": s.pk})
            resp = auth_client.post(url)
    assert resp.status_code == 200
    s.refresh_from_db()
    assert s.status == "completed"
    assert s.progress == 100
    assert s.pid is None or s.pid == 12345
    assert isinstance(s.result, dict)

@pytest.mark.django_db
def test_run_invalid_type_returns_400(auth_client, users):
    me, _ = users
    s = Scan.objects.create(user=me, name="Bad", target="127.0.0.1", scan_type="open_ports")
    Scan.objects.filter(pk=s.pk).update(scan_type="unknown")

    url = reverse("scan-run", kwargs={"pk": s.pk})
    resp = auth_client.post(url)
    assert resp.status_code == 400

@pytest.mark.django_db
def test_run_exception_sets_failed(auth_client, users):
    me, _ = users
    s = Scan.objects.create(user=me, name="Oops", target="127.0.0.1", scan_type="open_ports")

    with patch("scans.views.subprocess.Popen", side_effect=RuntimeError("boom")):
        url = reverse("scan-run", kwargs={"pk": s.pk})
        resp = auth_client.post(url)
    assert resp.status_code == 500
    s.refresh_from_db()
    assert s.status == "failed"

@pytest.mark.django_db
def test_cancel_happy_path(auth_client, users):
    me, _ = users
    s = Scan.objects.create(user=me, name="C1", target="127.0.0.1", scan_type="open_ports",
                            status="running", pid=2222)
    with patch("scans.views.os.kill") as mkill:
        url = reverse("scan-cancel", kwargs={"pk": s.pk})
        resp = auth_client.post(url)
    assert resp.status_code == 200
    s.refresh_from_db()
    assert s.status == "cancelled"

@pytest.mark.django_db
def test_cancel_not_running_or_missing_pid(auth_client, users):
    me, _ = users
    s1 = Scan.objects.create(user=me, name="C2", target="127.0.0.1", scan_type="open_ports", status="pending")
    resp1 = auth_client.post(reverse("scan-cancel", kwargs={"pk": s1.pk}))
    assert resp1.status_code == 400

    s2 = Scan.objects.create(user=me, name="C3", target="127.0.0.1", scan_type="open_ports", status="running", pid=None)
    resp2 = auth_client.post(reverse("scan-cancel", kwargs={"pk": s2.pk}))
    assert resp2.status_code == 400

@pytest.mark.django_db
def test_cancel_kill_fails_returns_500(auth_client, users):
    me, _ = users
    s = Scan.objects.create(user=me, name="C4", target="127.0.0.1", scan_type="open_ports", status="running", pid=999)
    with patch("scans.views.os.kill", side_effect=OSError("nope")):
        resp = auth_client.post(reverse("scan-cancel", kwargs={"pk": s.pk}))
    assert resp.status_code == 500
