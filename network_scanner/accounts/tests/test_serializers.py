import pytest
from django.contrib.auth import get_user_model
from accounts.serializers import (
    RegisterSerializer, UserSerializer, ActivityLogSerializer, CustomTokenObtainPairSerializer
)
from accounts.models import ActivityLog

@pytest.mark.django_db
def test_register_serializer_success():
    data = {
        "username": "newuser",
        "first_name": "New",
        "last_name": "User",
        "password": "Str0ngP@ssw0rd!",
        "password2": "Str0ngP@ssw0rd!",
    }
    ser = RegisterSerializer(data=data)
    assert ser.is_valid(), ser.errors
    user = ser.save()
    assert user.id is not None
    assert user.username == "newuser"
    assert user.check_password("Str0ngP@ssw0rd!")

@pytest.mark.django_db
def test_register_serializer_password_mismatch():
    data = {
        "username": "baduser",
        "first_name": "Bad",
        "last_name": "User",
        "password": "Str0ngP@ssw0rd!",
        "password2": "DifferentP@ss1!",
    }
    ser = RegisterSerializer(data=data)
    assert not ser.is_valid()
    assert "password" in ser.errors

@pytest.mark.django_db
def test_user_and_activity_serializers_roundtrip():
    U = get_user_model()
    u = U.objects.create_user(username="c", password="Str0ngP@ss!", first_name="C", last_name="L")
    u_json = UserSerializer(u).data
    assert set(u_json.keys()) == {"id", "username", "first_name", "last_name"}

    log = ActivityLog.objects.create(user=u, action="login")
    log_json = ActivityLogSerializer(log).data
    assert set(log_json.keys()) == {"id", "action", "timestamp"}
    assert log_json["action"] == "login"

@pytest.mark.django_db
def test_custom_token_obtain_pair_serializer_includes_user_fields():
    U = get_user_model()
    u = U.objects.create_user(username="jwtuser", password="Str0ngP@ss!", first_name="J", last_name="W")
    ser = CustomTokenObtainPairSerializer(data={"username": "jwtuser", "password": "Str0ngP@ss!"})
    assert ser.is_valid(), ser.errors
    data = ser.validated_data
    for k in ["access", "refresh", "id", "username", "first_name", "last_name"]:
        assert k in data
    assert data["id"] == u.id
