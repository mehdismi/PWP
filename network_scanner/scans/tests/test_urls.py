from django.urls import reverse, resolve

def test_urls_resolve():
    assert reverse("scan-list")
    assert reverse("dashboard-summary")
    assert resolve(reverse("scan-run", kwargs={"pk": 1})).url_name == "scan-run"
    assert resolve(reverse("scan-cancel", kwargs={"pk": 1})).url_name == "scan-cancel"
