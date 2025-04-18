import secrets
import string
from Administrador import models as Admin_models
from . import models as Api_models
from . import ecc




def generar_uid():
    caracteres = string.ascii_lowercase + string.digits
    uid = ''
    while uid == '' or Api_models.Credencial.objects.filter(uid=uid).exists():
        uid = ''.join(secrets.choice(caracteres) for _ in range(10))
    return uid





def crear_credencial(entidad_id:int,tipo_sistema:str,update=False):
    #Validar entidad
    entidad = None
    try:
        entidad = Admin_models.Entidad.objects.get(id=entidad_id)
    except Exception as e:
        return None,str(e)
    
    #validar tipo de sistema
    if not tipo_sistema in Api_models.tipo_sistema:
        return None,"Tipo de sistema inválido."
    
    #validar si existe esta credencial
    credencial = None
    try:
        credencial = Api_models.Credencial.objects.get(entidad_id=entidad,tipo_sistema=tipo_sistema)
        if update==False:
            return None,'La entidad ya posee esta credencial, si desea actualizarla debe revocarla primero.'
    except Exception:
        pass
    
    #generando claves de firma digital
    private_pem, public_pem = ecc.generate_ecdsa_key_pair()

    #generando o actualizando credencial
    uid = generar_uid()
    if credencial:
        credencial.public_key = public_pem
        credencial.private_key = private_pem
        
        credencial.uid = uid
    else:
        credencial = Api_models.Credencial(entidad_id=entidad,uid=uid,tipo_sistema=tipo_sistema,public_key=public_pem,private_key=private_pem)
    credencial.save()
    return credencial,'OK'
    
