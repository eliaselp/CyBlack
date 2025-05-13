from django.urls import path,include
from . import views
urlpatterns = [
    path('',views.Admin_Dashboard.as_view(),name='admin_dashboard'),
    path('entidades/',views.Entidades.as_view(),name='entidades'),
    path('entidades/nueva/',views.Nueva_Entidad.as_view(),name='nueva_entidad'),
    path('entidades/<int:id>/',views.Editar_Entidad.as_view(),name='editar_entidad'),
    path('entidades/eliminar/',views.Eliminar_Entidad.as_view(),name='eliminar_entidad'),
    
    path('credenciales/',views.Credenciales.as_view(),name='credenciales'),
    path('credenciales/nueva/',views.Nueva_Credencial.as_view(),name='nueva_credencial'),
    path('credenciales/renovar/',views.Renovar_credencial.as_view(),name="renovar_credencial"),
    path('credenciales/revocar/',views.Revocar_credencial.as_view(),name="revocar_credencial"),

    path('lista_negra/',include('Lista_negra.urls')),
    path('ajustes/',include('Ajustes.urls')),

    path('estadistica/',views.Estadistica.as_view(),name="estadistica")
]


