from django.urls import path,include
from . import views
urlpatterns = [
    path('get_qr_2fa/',views.get_qr_2fa,name='get_qr_2fa'),
    path('setup_2fa/',views.setup_2fa,name="setup_2fa"),
    path('remove_2fa',views.remove_2fa,name='remove_2fa'),
]


