from django.shortcuts import render

from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse,HttpRequest
from . import models as Api_models, ecc
from .Base64JsonConvert import Base64JsonConverter
from Lista_negra import views as Lista_negra_views
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction

@csrf_exempt
def set_secure_net(request: HttpRequest):
    # Verificación rápida del método HTTP
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)
    
    # Obtención eficiente de parámetros
    pub_key_cif = request.POST.get('public_key_cif')
    api_key = request.POST.get('api_key')
    uid = request.POST.get('uid')
    
    # Validación temprana de parámetros
    if not all([pub_key_cif, api_key, uid]):
        return JsonResponse({'error': 'Parámetros faltantes'}, status=400)
    
    try:
        # Consulta optimizada a la base de datos
        with transaction.atomic():
            credencial = (
                Api_models.Credencial.objects
                .select_for_update()  # Bloqueo para evitar condiciones de carrera
                .only('id', 'ntw_sec_pv')  # Solo los campos necesarios
                .get(public_key=api_key, uid=uid)
            )
            
            # Generación de claves ECC optimizada
            private_key, public_key = ecc.generate_keys()
            
            # Actualización atómica
            credencial.ntw_sec_pv = private_key
            credencial.save(update_fields=['ntw_sec_pv'])  # Solo actualiza el campo necesario
            
            # Cifrado de la clave pública
            encrypted_pub_key = ecc.encrypt_message(
                public_key=pub_key_cif,
                message=public_key
            )
            
            return JsonResponse({
                'status': 'success',
                'public_key': encrypted_pub_key
            }, json_dumps_params={'separators': (',', ':')})  # JSON más compacto
            
    except ObjectDoesNotExist:
        # Log seguro sin exponer detalles internos
        return JsonResponse({'error': 'Credenciales inválidas'}, status=403)
        
    except Exception as e:
        # Manejo genérico de errores (sin input() en producción)
        return JsonResponse({'error': 'Error interno del servidor'}, status=500)








@csrf_exempt
@require_POST
@transaction.atomic
def add_url(request: HttpRequest):
    try:
        post_data = request.POST
        data = post_data.get('data')
        api_key = post_data.get('api_key')
        uid = post_data.get('uid')
        firma = post_data.get('firma')

        if not all([data, api_key, uid, firma]):
            return JsonResponse({'error': 'Parámetros incompletos'}, status=400)

        try:
            credencial = Api_models.Credencial.objects.only('public_key', 'ntw_sec_pv', 'entidad_id').get(
                public_key=api_key, uid=uid
            )
        except Api_models.Credencial.DoesNotExist:
            return JsonResponse({'error': 'Acceso Denegado'}, status=405)

        if not ecc.verify_signature(message=data, signature_hex=firma, public_key_pem=credencial.public_key):
            return JsonResponse({'error': 'Firma no válida'}, status=405)

        try:
            decrypted_data = ecc.decrypt_message(private_key=credencial.ntw_sec_pv, encrypted_message=data)
            parsed_data = Base64JsonConverter.base64_to_dict(base64_str=decrypted_data)
        except Exception as e:
            return JsonResponse({'error': 'Error al descifrar o parsear datos'}, status=400)

        return Lista_negra_views.CrearURLEvidenciaView(
            FILES=request.FILES, data=parsed_data, entidad=credencial.entidad_id
        )

    except Exception as e:
        return JsonResponse({'error': f'Error interno: {str(e)}'}, status=500)






@csrf_exempt
@require_POST
@transaction.atomic
def query_monitoreo(request: HttpRequest):
    try:
        post_data = request.POST
        data = post_data.get('data')
        api_key = post_data.get('api_key')
        uid = post_data.get('uid')
        firma = post_data.get('firma')

        if not all([data, api_key, uid, firma]):
            return JsonResponse({'error': 'Parámetros incompletos'}, status=400)

        try:
            credencial = Api_models.Credencial.objects.only('public_key', 'ntw_sec_pv', 'entidad_id').get(
                public_key=api_key, uid=uid
            )
        except Api_models.Credencial.DoesNotExist:
            return JsonResponse({'error': 'Acceso Denegado'}, status=405)

        if not ecc.verify_signature(message=data, signature_hex=firma, public_key_pem=credencial.public_key):
            return JsonResponse({'error': 'Firma no válida'}, status=405)

        try:
            decrypted_data = ecc.decrypt_message(private_key=credencial.ntw_sec_pv, encrypted_message=data)
            parsed_data = Base64JsonConverter.base64_to_dict(base64_str=decrypted_data)
        except Exception as e:
            return JsonResponse({'error': 'Error al descifrar o parsear datos'}, status=400)

        return Lista_negra_views.Query_access(
            data=parsed_data, entidad=credencial.entidad_id
        )

    except Exception as e:
        return JsonResponse({'error': f'Error interno: {str(e)}'}, status=500)
