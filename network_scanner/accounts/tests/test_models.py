import pytest
from django.contrib.auth import get_user_model
from accounts.models import ActivityLog

@pytest.mark.django_db
def test_custom_user_str():
    U = get_user_model()
    u = U.objects.create_user(username="alice", password="Str0ngP@ss!", first_name="A", last_name="L")
    assert str(u) == "alice"

@pytest.mark.django_db
def test_activity_log_str():
    U = get_user_model()
    u = U.objects.create_user(username="bob", password="Str0ngP@ss!", first_name="B", last_name="O")
    log = ActivityLog.objects.create(user=u, action="did something")
    s = str(log)
    assert "bob" in s and "did something" in s
