from django.shortcuts import render


from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse,HttpRequest
from . import models as Api_models, ecc
from .Base64JsonConvert import Base64JsonConverter
from Lista_negra import views as Lista_negra_views

@csrf_exempt
def set_secure_net(request:HttpRequest):
    if request.POST:
        pub_key_cif = request.POST.get('public_key_cif')
        api_key = request.POST.get('api_key')
        uid = request.POST.get('uid')
        
        try:
            credencial = Api_models.Credencial.objects.get(public_key=api_key, uid=uid)
            private_key, public_key = ecc.generate_keys()
            credencial.ntw_sec_pv = private_key
            credencial.save()

            public_key = ecc.encrypt_message(public_key=pub_key_cif,message=public_key)

            return JsonResponse({
                'status': 'success',
                'public_key': public_key
            })
        except Exception as e:
            return JsonResponse({'error': 'Acceso Denegado'}, status=405) 
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)        



@csrf_exempt
def add_url(request:HttpRequest):
    if request.method == 'POST':
        #try:
        data = request.POST.get('data')
        api_key = request.POST.get('api_key')
        uid = request.POST.get('uid')
        firma = request.POST.get('firma')
        credencial = None
        try:
            credencial = Api_models.Credencial.objects.get(public_key=api_key, uid=uid)
        except Exception as e:
            return JsonResponse({'error': 'Acceso Denegado'}, status=405)
        
        if not ecc.verify_signature(message=data, signature_hex=firma,public_key_pem=credencial.public_key):
            return JsonResponse({'error': 'Acceso Denegado'}, status=405)

        data = ecc.decrypt_message(private_key=credencial.ntw_sec_pv,encrypted_message=data)

        data = Base64JsonConverter.base64_to_dict(base64_str=data)

        response = Lista_negra_views.CrearURLEvidenciaView(FILES=request.FILES,data=data)

        return response
        #except Exception as e:
        #    return JsonResponse({'error': f'{e}'}, status=500)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)