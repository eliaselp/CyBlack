from django.urls import path
from . import views

urlpatterns = [
    path('set_secure_net/',views.set_secure_net,name='set_secure_net'),
    path('add_url/',views.add_url,name='add_url'),
]