from django.urls import path
from . import views
urlpatterns = [
    path('',views.Lista_negra.as_view(),name='lista_negra'),
    path('aplicar_filtros/',views.aplicar_filtros,name="aplicar_filtros")
]


