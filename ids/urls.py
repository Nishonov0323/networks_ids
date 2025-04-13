# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router for DRF views
router = DefaultRouter()
router.register(r'flows', views.NetworkFlowViewSet)
router.register(r'alerts', views.AlertViewSet)
router.register(r'rules', views.DetectionRuleViewSet)
router.register(r'models', views.MLModelViewSet)
router.register(r'hierarchical-models', views.HierarchicalModelViewSet)
router.register(r'training-jobs', views.TrainingJobViewSet)
router.register(r'interfaces', views.NetworkInterfaceViewSet)

# URL patterns
urlpatterns = [
    # Main dashboard view
    path('', views.dashboard, name='dashboard'),

    # API endpoints
    path('api/', include(router.urls)),
    path('api/ingest/', views.ingest_packet, name='ingest_packet'),
    path('api/statistics/detailed/', views.get_statistics, name='get_statistics'),  # Renamed and changed path
    path('api/statistics/', views.statistics, name='statistics'),
    path('settings/', views.settings_page, name='settings_page'),
    path('flows/', views.flows_page, name='flows'),
    path('alerts/', views.alerts_page, name='alerts'),
    path('rules/', views.rules_page, name='rules'),
    path('models/', views.models_page, name='models'),
]