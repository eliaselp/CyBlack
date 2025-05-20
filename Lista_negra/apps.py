
# apps.py (de tu app principal)
from django.apps import AppConfig

class ListaNegraConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "Lista_negra"

    def ready(self):
        from . import signals  # Carga las señales