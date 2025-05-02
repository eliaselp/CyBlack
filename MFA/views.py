from django.shortcuts import render

# Create your views here.
# views.py
import pyotp
import qrcode
import qrcode.image.svg
from io import BytesIO
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_GET, require_POST
from django.conf import settings
from django.http import HttpRequest
from Ajustes import views as Ajustes_views
from django.views import View
from Index import views as Index_views


def validate_otp(secret_key, otp_code):
    """
    Valida un código OTP contra un secret_key
    Retorna True si es válido, False si no
    """
    if not secret_key or not otp_code:
        return False
    return pyotp.TOTP(secret_key).verify(otp_code)






@login_required
def get_qr_2fa(request):
    """
    Genera un nuevo QR para configurar 2FA
    Usa secret_mfa_temp para almacenar temporalmente el secreto
    """
    if not request.POST:
        try:
            # Generar o recuperar secreto temporal
            if not request.user.secret_mfa_temp:
                request.user.secret_mfa_temp = pyotp.random_base32()
                request.user.save()
            
            # Crear URI para Google Authenticator
            totp = pyotp.totp.TOTP(request.user.secret_mfa_temp)
            provisioning_uri = totp.provisioning_uri(
                name=request.user.email or request.user.username,
                issuer_name=getattr(settings, 'OTP_ISSUER_NAME', 'CyBlack')
            )
            
            # Generar QR como SVG
            img = qrcode.make(provisioning_uri, image_factory=qrcode.image.svg.SvgImage)
            buffer = BytesIO()
            img.save(buffer)
            qr_code = buffer.getvalue().decode('utf-8')
            
            return JsonResponse({
                'success': True,
                'qr_url': f"data:image/svg+xml;utf8,{qr_code}",
                'secret_key': request.user.secret_mfa_temp
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    else:
        return Ajustes_views.Ajustes.Notificacion(request=request)





@login_required
def setup_2fa(request):
    """
    Valida el codigo 2fa y establece de forma permanente la configuracion mfa previamente establecida
    """
    if request.POST:
        try:
            secret = request.user.secret_mfa_temp
            code = request.POST.get('otp_code')
            if validate_otp(secret_key=secret,otp_code=code):
                request.user.secret_mfa = request.user.secret_mfa_temp
                request.user.save()
                return Ajustes_views.Ajustes.Notificacion(request=request,Success="2FA establecido correctamente.")
            else:
                return Ajustes_views.Ajustes.Notificacion(request=request,Error="Codigo 2FA incorrecto.")
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    else:
        return Ajustes_views.Ajustes.Notificacion(request=request)




@login_required
def remove_2fa(request:HttpRequest):
    """
    Valida el codigo 2fa y establece de forma permanente la configuracion mfa previamente establecida
    """
    if request.POST:
        try:
            secret = request.user.secret_mfa
            code = request.POST.get('current_otp_code')
            if validate_otp(secret_key=secret,otp_code=code):
                request.user.secret_mfa = None
                request.user.secret_mfa_temp = None
                request.user.save()
                return Ajustes_views.Ajustes.Notificacion(request=request,Success="2FA eliminado correctamente.")
            else:
                return Ajustes_views.Ajustes.Notificacion(request=request,Error="Codigo 2FA incorrecto.")
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    else:
        return Ajustes_views.Ajustes.Notificacion(request=request)




