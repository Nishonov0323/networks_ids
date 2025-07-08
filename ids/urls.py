# ids/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('flows/', views.flows, name='flows'),
    path('api/new-flows/', views.get_new_flows, name='get_new_flows'),
    path('analysis/', views.analysis, name='analysis'),
    path('analysis/download/', views.download_analysis, name='download_analysis'),
    path('alerts/', views.alerts, name='alerts'),
    path('alerts/<int:alert_id>/', views.alert_detail, name='alert_detail'),
    path('rules/', views.rules, name='rules'),
]