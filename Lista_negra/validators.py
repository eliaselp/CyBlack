# validators.py
from django.core.exceptions import ValidationError
from django.template.defaultfilters import filesizeformat
from django.core.validators import BaseValidator

# Opción 1: Función simple (recomendada para tu caso)
def validate_file_size(value):
    max_size = 209715200  # 200MB
    if value.size > max_size:
        raise ValidationError(
            f'El archivo no puede exceder {filesizeformat(max_size)}. '
            f'Tamaño actual: {filesizeformat(value.size)}'
        )

# Opción 2: Clase basada en BaseValidator (alternativa)
class FileSizeValidator(BaseValidator):
    message = 'El archivo excede el tamaño máximo de %(limit_value)s.'
    code = 'file_size_limit'

    def compare(self, file, max_size):
        return file.size > max_size

    def clean(self, max_size):
        return filesizeformat(max_size)