
from django.contrib import admin
from django.urls import path,include
from Index import views as Index_views

urlpatterns = [
    path('',include('Index.urls')),
    path('dashboard/admin/',include('Administrador.urls')), 
]
