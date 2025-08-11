"""URL routing for user authentication, profile, activity, and password management."""
from django.urls import path
from .views import RegisterView, LogoutView,UserProfileView,ActivityLogListView,ChangePasswordView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/<int:id>/', UserProfileView.as_view(), name='profile'),
    path('activity/', ActivityLogListView.as_view(), name='activity'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),

]
