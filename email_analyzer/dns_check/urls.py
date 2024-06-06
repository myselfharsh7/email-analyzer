from django.urls import path
from . import views


urlpatterns = [
    path('dnscheck/', views.dns_check, name='dns_check'),
]
