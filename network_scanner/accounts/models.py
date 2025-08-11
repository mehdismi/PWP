"""Defines custom user model and user activity log model."""
# pylint: disable=no-member


from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    """Custom user model extending Django's AbstractUser."""
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    def __str__(self):
        """String representation of the user."""
        return str(self.username)

class ActivityLog(models.Model):
    """Model to track user actions over time."""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='activity_logs')
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """Return readable string representation of activity."""
        return f"{self.user.username} - {self.action} - {self.timestamp}"
