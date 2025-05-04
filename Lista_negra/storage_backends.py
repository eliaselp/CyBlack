# storage_backends.py
from django.core.files.storage import FileSystemStorage


class CustomStorage(FileSystemStorage):
    def get_available_name(self, name, max_length=None):
        # Lógica para nombres de archivo únicos
        return super().get_available_name(name, max_length)

