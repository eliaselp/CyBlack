from django.urls import path,include
from . import views

urlpatterns = [
    path('',views.Ajustes.as_view(),name='ajustes'),
    path('cambiar_password/',views.Cambiar_contrasenna.as_view(),name="cambiar_password"),
    path('remote_logout/',views.cerrar_sesion_remota,name="remote_logout"),
    path('cerrar_todas_las_sesiones',views.cerrar_todas_las_sesiones,name="cerrar_todas_las_sesiones"),
    path('mfa/',include('MFA.urls'))
]