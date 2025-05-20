from django.db import models
from django.core.validators import FileExtensionValidator
from .validators import validate_file_size  # Importamos la función validadora
import hashlib
import json
from . import storage_backends
from Administrador import models as Admin_models

# Choices deberían ser tuplas de pares (valor, etiqueta)
OBJETIVO_CHOICES = [
    ('ILICITO', 'Contenido ilícito'),
    ('ECONOMIA', 'Economía'),
    ('INFRAESTRUCTURA', 'Infraestructura'),
]

METODO_CHOICES = [
    ('ENGAÑO', 'Engaño: Phishing, Scam, etc...'),
    ('TECNICO', 'Técnico: Malware, exploit, etc...'),
    ('EVASION', 'Evasión: VPN, Proxies, etc...')
]

IMPACTO_LEGAL_CHOICES = [
    ('GRAVE', 'Grave'),
    ('MODERADO', 'Moderado'),
    ('LEVE', 'Leve')
]

PROTOCOLO_CHOICES = [
    ('HTTP', 'HTTP'),
    ('HTTPS', 'HTTPS'),
]

class URL_Maliciosa(models.Model):
    protocolo = models.CharField(
        max_length=10,
        choices=PROTOCOLO_CHOICES,
        null=False
    )
    puerto = models.IntegerField(null=False)
    url = models.TextField(null=False,unique=True)
    ip = models.GenericIPAddressField(null=True)

    # Clasificaciones
    objetivo = models.CharField(
        max_length=20,
        choices=OBJETIVO_CHOICES,
        null=True
    )
    metodo = models.CharField(
        max_length=20,
        choices=METODO_CHOICES,
        null=True
    )
    impacto_legal = models.CharField(
        max_length=20,
        choices=IMPACTO_LEGAL_CHOICES,
        null=True
    )

    descripcion = models.TextField(null=True)
    
    # Fechas
    fecha_deteccion = models.DateTimeField(auto_now_add=True)
    ultima_acceso = models.DateTimeField(auto_now=True)
    total_accesos = models.IntegerField(default=1,null=False)

    def __str__(self):
        return f"{self.url} ({self.ip})"




class Acceso_Denegado(models.Model):
    url = models.ForeignKey(URL_Maliciosa, on_delete=models.CASCADE,related_name='accesos_denegados',null=True)
    fecha = models.DateTimeField(auto_now_add=True)
    entidad = models.ForeignKey(Admin_models.Entidad, on_delete=models.SET_NULL, null=True, related_name='accesos_denegados')
    def __str__(self):
        return f"Acceso a {self.url} por {self.entidad}"


class Acceso_Allowed(models.Model):
    fecha = models.DateTimeField(auto_now_add=True)
    entidad = models.ForeignKey(Admin_models.Entidad, on_delete=models.SET_NULL, null=True, related_name='accesos_permitidos')
    def __str__(self):
        return f"Acceso de {self.entidad} realizado el {self.fecha}"



class Evidencia(models.Model):
    # Relación con la URL maliciosa
    url_maliciosa = models.ForeignKey(
        URL_Maliciosa,
        on_delete=models.CASCADE,
        related_name='evidencias'
    )
    
    # Método de detección
    METODO_DETECCION_CHOICES = [
        ('FIRMA', 'Análisis de Firmas'),
        ('HEURISTICA', 'Heurística'),
        ('MACHINE_LEARNING', 'Machine Learning/IA'),
        ('REPUTACION', 'Análisis de Reputación'),
        ('SANDBOX', 'Sandboxing'),
        ('HEADERS', 'Análisis de Headers HTTP'),
        ('SSL', 'Detección de Certificados SSL'),
        ('SCRAPING', 'Web Scraping'),
        ('DNS', 'DNS Analysis'),
        ('HONEYPOT', 'HoneyPot'),
    ]
    metodo_deteccion = models.CharField(
        max_length=20,
        choices=METODO_DETECCION_CHOICES
    )
    entidad = models.ForeignKey(Admin_models.Entidad, on_delete=models.SET_NULL, null=True, related_name='evidencias')    
    # Campos de evidencia
    descripcion = models.TextField(blank=True)
    archivo = models.FileField(
        upload_to='evidencias/%Y/%m/%d/',
        null=True,
        blank=True,
        validators=[
            FileExtensionValidator(
                allowed_extensions=[
                    'png', 'jpg', 'jpeg', 'gif',
                    'pdf',
                    'txt', 'log',
                    'json', 'xml',
                    'pcap', 'har',
                    'zip', 'rar', 'tar', 'gz',
                    'csv', 'xlsx', 'docx'
                ]
            ),
            validate_file_size  # Usamos la función validadora en lugar de la clase
        ],
        storage=storage_backends.CustomStorage(),
        max_length=500,
        help_text="Formatos permitidos: imágenes, documentos, archivos de red y comprimidos",
        verbose_name="Archivo de evidencia"
    )
    datos_tecnicos = models.JSONField(default=dict, blank=True)
    
    # Fechas
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Evidencia Técnica"
        verbose_name_plural = "Evidencias Técnicas"
        ordering = ['-fecha_creacion']


    def __str__(self):
        return f"Evidencia #{self.id} - {self.get_metodo_deteccion_display()}"




# Configuración de autoeliminación de archivos
from django.db.models.signals import post_delete
from django.dispatch import receiver

@receiver(post_delete, sender=Evidencia)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    if instance.archivo:
        instance.archivo.delete(save=False)







from auditlog.registry import auditlog

# Registra el modelo para auditoría
auditlog.register(URL_Maliciosa)
auditlog.register(Evidencia)
auditlog.register(Acceso_Allowed)
auditlog.register(Acceso_Denegado)