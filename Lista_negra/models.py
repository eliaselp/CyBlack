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
    ('FTP', 'FTP'),
    ('SFTP', 'SFTP'),
    ('SMTP', 'SMTP'),
    ('IMAP', 'IMAP'),
    ('POP3', 'POP3'),
    ('TELNET', 'Telnet'),
    ('SSH', 'SSH'),
    ('RDP', 'RDP'),
    ('WEBDAV', 'WebDAV')
]

class URL_Maliciosa(models.Model):
    protocolo = models.CharField(
        max_length=10,
        choices=PROTOCOLO_CHOICES,
        null=False
    )
    puerto = models.IntegerField(null=False)
    url = models.TextField(null=False)
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




class Acceso(models.Model):
    url = models.ForeignKey(URL_Maliciosa, on_delete=models.CASCADE)
    fecha = models.DateTimeField(auto_now_add=True)
    entidad = models.ForeignKey(Admin_models.Entidad, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return f"Acceso a {self.url} por {self.entidad}"





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
    hash_sha256 = models.CharField(max_length=64, blank=True)
    
    # Fechas
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Evidencia Técnica"
        verbose_name_plural = "Evidencias Técnicas"
        ordering = ['-fecha_creacion']

    def _generar_hash(self):
        """Genera un hash SHA256 único basado en todos los campos relevantes."""
        hash_obj = hashlib.sha256()
        
        campos = [
            str(self.metodo_deteccion),
            str(self.descripcion),
            json.dumps(self.datos_tecnicos, sort_keys=True),
            str(self.url_maliciosa_id)
        ]
        
        if self.archivo:
            self.archivo.seek(0)
            campos.append(self.archivo.read().decode('utf-8', errors='ignore'))
            self.archivo.seek(0)
        
        hash_obj.update("|".join(campos).encode('utf-8'))
        return hash_obj.hexdigest()

    def save(self, *args, **kwargs):
        self.hash_sha256 = self._generar_hash()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Evidencia #{self.id} - {self.get_metodo_deteccion_display()}"




# Configuración de autoeliminación de archivos
from django.db.models.signals import post_delete
from django.dispatch import receiver

@receiver(post_delete, sender=Evidencia)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    if instance.archivo:
        instance.archivo.delete(save=False)