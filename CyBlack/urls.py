
from django.contrib import admin
from django.urls import path,include
from Index import views as Index_views

urlpatterns = [
    path('', Index_views.Login.as_view(),name='login'),
    path('logout/',Index_views.Logout.as_view(),name='logout'),
    path('redirect/',Index_views.redirigir_usuario,name='redirect'),
    path('dashboard/admin/',include('Administrador.urls')), 
]
