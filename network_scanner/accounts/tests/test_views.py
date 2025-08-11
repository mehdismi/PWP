"""Test cases for the accounts app endpoints using pytest and APIClient."""
import pytest
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model

User = get_user_model()

@pytest.mark.django_db
def test_user_registration():
    """Test user registration endpoint."""
    client = APIClient()
    payload = {
        "username": "testuser",
        "first_name": "Test",
        "last_name": "User",
        "password": "StrongPass123",
        "password2": "StrongPass123"
    }
    response = client.post('/api/v1/accounts/register/', payload)
    assert response.status_code == 201
    assert response.data['username'] == "testuser"

@pytest.mark.django_db
def test_user_login():
    """Test JWT login and token retrieval."""
    user = User.objects.create_user(username='loginuser', password='Login1234')
    client = APIClient()

    response = client.post('/api/v1/token/', {
        'username': 'loginuser',
        'password': 'Login1234'
    })

    assert response.status_code == 200
    assert 'access' in response.data
    assert 'refresh' in response.data

@pytest.mark.django_db
def test_user_profile_view():
    """Test user profile retrieval for authenticated user."""
    user = User.objects.create_user(username='profileuser', password='TestPass123', first_name="Mahdi", last_name="Salmani")
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.get(f'/api/v1/accounts/profile/{user.id}/')

    assert response.status_code == 200
    assert response.data['username'] == 'profileuser'
    assert response.data['first_name'] == 'Mahdi'

@pytest.mark.django_db
def test_change_password():
    """Test password change functionality."""
    user = User.objects.create_user(username='changepw', password='OldPass123')
    client = APIClient()
    client.force_authenticate(user=user)

    payload = {
        "old_password": "OldPass123",
        "new_password": "NewSecure456"
    }

    response = client.put('/api/v1/accounts/change-password/', payload)

    assert response.status_code == 200
    assert response.data['message'] == 'Password updated successfully'
