
from django.contrib.auth.models import User
from django.db import models

from Administrador import models as Admin_Models

# Create your models here.



tipo_sistema = ('Sistema de detección', 'Sistema de monitoreo')
class Credencial(models.Model):
    entidad_id = models.ForeignKey(Admin_Models.Entidad, on_delete=models.CASCADE, null=False)
    uid = models.TextField(null=False, blank=False, unique=True)
    tipo_sistema = models.TextField(null=True, blank=False)
    public_key = models.TextField(null=False, unique=True)
    private_key = models.TextField(null=False, unique=True)
    ntw_sec_pub = models.TextField(null=True, blank=True)
    ultima_actualizacion = models.DateTimeField(auto_now=True)



