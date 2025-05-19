from django.urls import path,include
from . import views as Entidad_views
from Administrador.views import Estadistica
urlpatterns = [
    path('',Entidad_views.Entidad_Dashboard.as_view(),name="entidad_dashboard"),
    path('entidades/',Entidad_views.Entidades.as_view(),name="entidades"),
    path('entidades/estadisticas/',Estadistica.as_view(),name="estadisticas"),
    path('lista_negra/',include('Lista_negra.urls')),
]
