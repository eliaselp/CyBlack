from django.db import models
from django.contrib.auth.models import User
# Create your models here.


tipos_entidades = ('Empresa Privada','Organización sin fines de lucro', 'Institución Pública')
tipos_documentos_identidad = ('Carnet de Identidad', 'Pasaporte')
class Entidad(models.Model):
    userid = models.OneToOneField(User,on_delete=models.CASCADE,null=False)
    nombre_entidad = models.TextField(null=False,blank=False)
    tipo_entidad = models.TextField(null=False,blank=False)
    direccion_fiscal = models.TextField(null=False,blank=False,unique=True)
    telefono_entidad = models.TextField(null=False,blank=False,unique=True)
    email_institucional = models.EmailField(null=False,blank=False,unique=True)
    sitio_web = models.URLField(null=True,blank=True,unique=True)
    sector_economico = models.TextField(null=False,blank=False)

    #responsable
    nombre_responsable = models.TextField(null=False,blank=False, unique=True)
    cargo_puesto = models.TextField(null=False,blank=False)
    tipo_documento_identidad = models.TextField(null=False,blank=False)
    numero_documento = models.TextField(null=False,blank=False)
    email_responsable = models.EmailField(null=False,blank=False,unique=True)
    telefono_responsable = models.TextField(null=False,blank=False,unique=True)
    direccion_responsable = models.TextField(null=False,blank=False,unique=True)
    


