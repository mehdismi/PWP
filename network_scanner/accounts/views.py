# pylint: disable=no-member
"""Views for user registration, authentication, profile management, and activity logging."""
from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from .models import ActivityLog,CustomUser
from .serializers import UserSerializer,ActivityLogSerializer,RegisterSerializer

class RegisterView(generics.CreateAPIView):
    """Handles user registration."""
    queryset = CustomUser.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = RegisterSerializer

class LogoutView(APIView):
    """Handles user logout by blacklisting refresh token."""
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        """Logout the current user by blacklisting the refresh token."""
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=205)
        except Exception:
            return Response(status=400)



class UserProfileView(generics.RetrieveUpdateDestroyAPIView):
    """View to retrieve, update or delete the authenticated user's profile."""
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    lookup_field = 'id'
    def get_queryset(self):
        return CustomUser.objects.filter(id=self.request.user.id)

class ActivityLogListView(generics.ListAPIView):
    """Returns a list of activity logs for the authenticated user."""
    serializer_class = ActivityLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ActivityLog.objects.filter(user=self.request.user).order_by('-timestamp')

class ChangePasswordSerializer(serializers.Serializer):
    """Serializer to handle password change."""
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):
        validate_password(value)
        return value

    def validate(self, attrs):
        user = self.context['request'].user
        if not user.check_password(attrs['old_password']):
            raise serializers.ValidationError({"old_password": "Wrong old password."})
        return attrs

    def create(self, validated_data):
        """Unused create method to satisfy BaseSerializer requirements."""
        return self.instance

    def update(self, instance, validated_data):
        """Update the authenticated user's password."""
        instance.set_password(validated_data['new_password'])
        instance.save()
        return instance


class ChangePasswordView(generics.UpdateAPIView):
    """Allows an authenticated user to change their password."""
    serializer_class = ChangePasswordSerializer
    model = CustomUser
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        return self.request.user
    def update(self, request, *args, **kwargs):
        """Update the authenticated user's password."""
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.update(request.user, serializer.validated_data)
        return Response({"message": "Password updated successfully"}, status=200)


from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer

class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom JWT login view that includes user info in response."""
    serializer_class = CustomTokenObtainPairSerializer
