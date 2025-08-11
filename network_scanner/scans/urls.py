"""URL configuration for the scans app."""
from rest_framework.routers import DefaultRouter
from django.urls import path, include
from .views import ScanViewSet,DashboardSummaryView

router = DefaultRouter()
router.register(r'', ScanViewSet, basename='scan')

urlpatterns = [
    path('dashboard/summary/', DashboardSummaryView.as_view(), name='dashboard-summary'),
    path('', include(router.urls)),
]
