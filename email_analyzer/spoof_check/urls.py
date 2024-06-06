from django.urls import path
from . import views

urlpatterns = [
    path('spoof check', views.spoof_check, name='spoof_check'),
]
