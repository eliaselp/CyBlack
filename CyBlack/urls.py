
from django.contrib import admin
from django.urls import path,include
from Index import views as Index_views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('',include('Index.urls')),
    path('dashboard/admin/',include('Administrador.urls')), 
    path('dashboard/entidad/',include('Entidad.urls')),
    path('api/',include('Api.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) 
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
