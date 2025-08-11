"""Negative test cases for user registration, login, profile access, and password change."""
import pytest
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.mark.django_db
def test_register_passwords_do_not_match():
    """Should return 400 if passwords do not match during registration."""
    client = APIClient()
    payload = {
        "username": "wrongpass",
        "first_name": "X",
        "last_name": "Y",
        "password": "pass1234",
        "password2": "pass5678"  # intentionally not matching
    }

    response = client.post('/api/v1/accounts/register/', payload)

    assert response.status_code == 400
    assert "password" in response.data


@pytest.mark.django_db
def test_register_existing_username():
    """Should return 400 if username is already taken."""
    User.objects.create_user(username='duplicateuser', password='Test1234')
    client = APIClient()

    payload = {
        "username": "duplicateuser",
        "first_name": "X",
        "last_name": "Y",
        "password": "Test1234",
        "password2": "Test1234"
    }

    response = client.post('/api/v1/accounts/register/', payload)

    assert response.status_code == 400
    assert "username" in response.data


@pytest.mark.django_db
def test_login_wrong_password():
    """Should return 401 if incorrect password is used."""
    User.objects.create_user(username='logintest', password='RightPass123')
    client = APIClient()

    response = client.post('/api/v1/token/', {
        'username': 'logintest',
        'password': 'WrongPass123'  # intentionally wrong
    })

    assert response.status_code == 401
    assert "No active account" in response.data['detail']


@pytest.mark.django_db
def test_profile_access_without_auth():
    """Should return 401 if unauthenticated user tries to access profile."""
    user = User.objects.create_user(username='unauthuser', password='test123')
    client = APIClient()

    response = client.get(f'/api/v1/accounts/profile/{user.id}/')

    assert response.status_code == 401
    assert "Authentication credentials were not provided." in response.data['detail']


@pytest.mark.django_db
def test_change_password_with_wrong_old_password():
    """Should return 400 if old password is incorrect during password change."""
    user = User.objects.create_user(username='changepw', password='correctOld')
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.put('/api/v1/accounts/change-password/', {
        "old_password": "wrongOld",
        "new_password": "newGood123"
    })

    assert response.status_code == 400
    assert "old_password" in response.data
