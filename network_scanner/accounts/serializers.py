"""Serializers for user registration, login, profile, and activity logging."""

from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import CustomUser,ActivityLog

class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    id = serializers.IntegerField(read_only=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:  # pylint: disable=too-few-public-methods
        """Serializer for user registration."""
        model = CustomUser
        fields = ('id','username', 'first_name', 'last_name', 'password', 'password2')

    def validate(self, attrs):
        """Ensure both password fields match."""
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        """Create user with hashed password."""
        user = CustomUser.objects.create(
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class UserSerializer(serializers.ModelSerializer):
    """Serializer for displaying user profile."""
    class Meta: # pylint: disable=too-few-public-methods
        model = CustomUser
        fields = ('id', 'username', 'first_name', 'last_name')


class ActivityLogSerializer(serializers.ModelSerializer): # pylint: disable=too-few-public-methods
    """Serializer for user activity logs."""
    class Meta: # pylint: disable=too-few-public-methods
        model = ActivityLog
        fields = ('id', 'action', 'timestamp')


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer): # pylint: disable=abstract-method, too-few-public-methods
    """Extend token serializer to include user data in response."""
    def validate(self, attrs):
        data = super().validate(attrs)
        data.update({
            'id': self.user.id,
            'username': self.user.username,
            'first_name': self.user.first_name,
            'last_name': self.user.last_name,
        })
        return data
