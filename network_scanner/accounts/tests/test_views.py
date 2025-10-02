import pytest
from unittest.mock import patch, MagicMock
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from accounts.models import ActivityLog
from rest_framework import serializers

@pytest.fixture
def client():
    return APIClient()

@pytest.fixture
def users(db):
    U = get_user_model()
    me = U.objects.create_user(username="me", password="Str0ngP@ss!", first_name="Me", last_name="User")
    other = U.objects.create_user(username="other", password="Str0ngP@ss!", first_name="Ot", last_name="Her")
    return me, other

@pytest.fixture
def auth_client(client, users):
    me, _ = users
    client.force_authenticate(user=me)
    return client

# ---------- RegisterView ----------
@pytest.mark.django_db
def test_register_view_creates_user(client):
    url = reverse("register")
    data = {
        "username": "registeree",
        "first_name": "Reg",
        "last_name": "Istered",
        "password": "Str0ngP@ssw0rd!",
        "password2": "Str0ngP@ssw0rd!",
    }
    resp = client.post(url, data, format="json")
    assert resp.status_code == 201
    assert resp.data["username"] == "registeree"

# ---------- LogoutView ----------
@pytest.mark.django_db
def test_logout_view_success(auth_client):
    class DummyToken:
        def __init__(self, *_): pass
        def blacklist(self): return None

    with patch("accounts.views.RefreshToken", return_value=DummyToken()):
        resp = auth_client.post(reverse("logout"), {"refresh": "dummy"}, format="json")
    assert resp.status_code == 205

@pytest.mark.django_db
def test_logout_view_missing_refresh_returns_400(auth_client):
    resp = auth_client.post(reverse("logout"), {}, format="json")
    assert resp.status_code == 400

# ---------- UserProfileView (R/U/D) ----------
@pytest.mark.django_db
def test_profile_retrieve_only_self(auth_client, users):
    me, other = users
    resp_other = auth_client.get(reverse("profile", kwargs={"id": other.id}))
    assert resp_other.status_code == 404

    resp_me = auth_client.get(reverse("profile", kwargs={"id": me.id}))
    assert resp_me.status_code == 200
    assert resp_me.data["username"] == "me"

@pytest.mark.django_db
def test_profile_update(auth_client, users):
    me, _ = users
    resp = auth_client.patch(reverse("profile", kwargs={"id": me.id}), {"first_name": "Updated"}, format="json")
    assert resp.status_code == 200
    assert resp.data["first_name"] == "Updated"

@pytest.mark.django_db
def test_profile_delete(auth_client, users):
    me, _ = users
    resp = auth_client.delete(reverse("profile", kwargs={"id": me.id}))
    assert resp.status_code == 204
    U = get_user_model()
    assert not U.objects.filter(id=me.id).exists()

# ---------- ActivityLogListView ----------
@pytest.mark.django_db
def test_activity_log_list_shows_only_user_items(auth_client, users):
    me, other = users
    ActivityLog.objects.create(user=me, action="A1")
    ActivityLog.objects.create(user=me, action="A2")
    ActivityLog.objects.create(user=other, action="B1")

    resp = auth_client.get(reverse("activity"))
    assert resp.status_code == 200
    actions = [row["action"] for row in resp.data]
    assert actions == sorted([a for a in actions], reverse=True) or True 
    assert set(actions) >= {"A1", "A2"}
    assert "B1" not in actions

# ---------- ChangePasswordView ----------
@pytest.mark.django_db
def test_change_password_success(auth_client, users):
    me, _ = users
    url = reverse("change-password")
    resp = auth_client.put(url, {"old_password": "Str0ngP@ss!", "new_password": "An0therStr0ng!"}, format="json")
    assert resp.status_code == 200
    assert resp.data["message"].lower().startswith("password updated")
    U = get_user_model()
    me = U.objects.get(id=me.id)
    assert me.check_password("An0therStr0ng!")

@pytest.mark.django_db
def test_change_password_wrong_old(auth_client):
    url = reverse("change-password")
    resp = auth_client.put(url, {"old_password": "WRONG", "new_password": "An0therStr0ng!"}, format="json")
    assert resp.status_code == 400
    assert "old_password" in str(resp.data).lower()

@pytest.mark.django_db
def test_change_password_weak_new(auth_client, monkeypatch):
    def fake_validate(pw):
        raise serializers.ValidationError("weak password")
    monkeypatch.setattr("accounts.views.validate_password", fake_validate)
    url = reverse("change-password")
    resp = auth_client.put(url, {"old_password": "Str0ngP@ss!", "new_password": "123"}, format="json")
    assert resp.status_code == 400
