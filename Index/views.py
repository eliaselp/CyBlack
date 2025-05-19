from django.shortcuts import redirect,render
from django.http import JsonResponse
from django.contrib.auth import authenticate, login as auth_login, logout
from django.views import View
from django.conf import settings
from django.utils.html import escape
from django.http import HttpRequest
from django_user_agents.utils import get_user_agent
from django.contrib.sessions.models import Session
from django.utils import timezone
from MFA import views as MFA_views
from django.contrib.auth.models import User
from Administrador import models as Admin_models
from . import utils, correo
from django.views.decorators.csrf import csrf_exempt


def redirigir_usuario(request):
    """Función centralizada para redirigir según el tipo de usuario"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    if request.user.is_staff:
        return redirect('admin_dashboard')
    else:
        return redirect('entidad_dashboard')

class Login(View):
    @staticmethod
    def Notificacion(request,Error=None,Success=None):
        if request.user.is_authenticated:
            return redirigir_usuario(request)
        return render(request, 'index.html',{
            'Error':Error,'Success':Success
        })
    
    def get(self, request):
        if request.user.is_authenticated:
            return redirigir_usuario(request)
        return render(request, 'index.html')

    @csrf_exempt
    def post(self, request):
        if request.user.is_authenticated:
            return redirigir_usuario(request)
            
        username = escape(request.POST.get('username'))
        password = escape(request.POST.get('password'))
        if not username or not password:
            return JsonResponse({
                'status': 'error',
                'message': 'Todos los campos son obligatorios.'
            }, status=400)
        
        try:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                auth_login(request, user)
                
                user_agent = get_user_agent(request)
                
                # Guardar información en la sesión  
                request.session['user_agent'] = str(user_agent)
                request.session['ip_address'] = request.META.get('REMOTE_ADDR')
                request.session['login_time'] = timezone.now().isoformat()
                
                # También puedes guardar los datos parseados directamente
                request.session['device_info'] = {
                    'navegador': user_agent.browser.family,
                    'version': user_agent.browser.version_string,
                    'sistema_operativo': user_agent.os.family,
                    'dispositivo': 'Móvil' if user_agent.is_mobile else 
                                'Tablet' if user_agent.is_tablet else 
                                'Computadora' if user_agent.is_pc else 
                                'Bot' if user_agent.is_bot else 'Desconocido'
                }

            
                if request.user.secret_mfa:
                    request.session['is_2fa_enabled'] = False
                else:
                    request.session['is_2fa_enabled'] = True

                request.session.set_expiry(settings.SESSION_COOKIE_AGE)
                request.session.save()


                # Respuesta JSON simple, el frontend manejará la recarga
                return JsonResponse({
                    'status': 'success',
                    'message': 'Autenticación exitosa'
                })
            
            return JsonResponse({
                'status': 'error',
                'message': 'Nombre de usuario o contraseña incorrectas'
            }, status=401)
            
        except Exception as e:
            # Log del error para debugging
            print(f"Error durante autenticación: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': 'Error del servidor'
            }, status=500)
        


class Logout(View):
    def get(self:HttpRequest,request):
        if request.user.is_authenticated:
            logout(request)
            return redirect("login")
        else:
            return redirigir_usuario(request)
     
            




class MFA(View):
    @staticmethod
    def Notificacion(request:HttpRequest,Error=None,Success=None):
        if request.user.is_authenticated and not request.user.secret_mfa is None and request.session['is_2fa_enabled'] == False:
            return render(request,'mfa.html',{
                'Error':Error,'Success':Success
            })
        else:
            return redirigir_usuario(request)
        

    def get(self,request:HttpRequest):
        if request.user.is_authenticated and not request.user.secret_mfa is None and request.session['is_2fa_enabled'] == False:
            return render(request,'mfa.html')
        else:
            return redirigir_usuario(request)
        
        
    def post(self,request:HttpRequest):
        if request.user.is_authenticated and not request.user.secret_mfa is None and request.session['is_2fa_enabled'] == False:
            otp_code = escape(str(request.POST.get('otp_code')).strip())
            if MFA_views.validate_otp(request.user.secret_mfa,otp_code=otp_code):
                request.session['is_2fa_enabled'] = True
                request.session.save()
                return redirigir_usuario(request)
            else:
                return MFA.Notificacion(request=request,Error='Codigo incorrecto')
        else:
            return redirigir_usuario(request)
        



class Recuperar_clave(View):
    @staticmethod
    def Notificacion(request:HttpRequest,step=1,Error=None,Success=None,user=None):
        if request.user.is_authenticated:
            return redirigir_usuario()
        return render(request,f'recuperar_clave/recuperar_{step}.html',{
            'Error':Error,'Success':Success,'user':user
        })
    

    def get(self, request:HttpRequest):
        if request.user.is_authenticated:
            return redirigir_usuario()
        return Recuperar_clave.Notificacion(request=request,step=1)


    def post(self, request:HttpRequest):
        if request.user.is_authenticated:
            return redirigir_usuario()
        
        opc = request.POST.get('opc')
        username=request.POST.get('username')
        user = User.objects.filter(username=username)
        if user.exists():
            user = user.first()
        else:
            return Recuperar_clave.Notificacion(request=request,step=1,Error="El usuario no existe.")
        
        if opc == "username":    
            email = None
            nombre = None
            if user.is_staff:
                email = user.email
                nombre = user.username
            else:
                entidad = Admin_models.Entidad.objects.get(userid=user)
                email = entidad.email_responsable
                nombre = entidad.nombre_responsable


            tocken = utils.generar_codigo_verificacion()
            user.tocken_mail = tocken
            user.save()
            Asunto = "Código de verificación para cambio de contraseña"
            Mensaje = f"""
Hola {nombre}:

Hemos recibido una solicitud para cambiar la contraseña de tu cuenta.

Para continuar con el proceso, por favor ingresa el siguiente código de verificación en la página correspondiente:

🔐 Código de verificación: {tocken}

Si no solicitaste este cambio, ignora este mensaje o contacta con nuestro equipo de soporte inmediatamente.

Gracias por usar nuestro servicio.
Saludos, CyBlack
"""
            
            correo.enviar_correo(email=email,Asunto=Asunto,s=Mensaje)
            return Recuperar_clave.Notificacion(request=request,step=2,Success="Código enviado correctamente. Revise su correo electrónico.",user=user)
        elif opc in ["verifyCode","cambiar_contraseña"]:
            code = request.POST.get('codigo')
            if user.tocken_mail == code:
                if opc == "verifyCode": 
                    return Recuperar_clave.Notificacion(request=request,step=3,Success="Código confirmado. Inserte su nueva contraseña.",user=user)
                elif opc == "cambiar_contraseña":
                    pass1 = request.POST.get('pass1')                    
                    pass2 = request.POST.get('pass2')
                    valid = utils.validar_contraseñas(pass1=pass1,pass2=pass2)
                    if valid == 'OK':
                        user.set_password(pass1)
                        user.save()
                        return Login.Notificacion(request=request,Success="Contraseña actualizada correctamente.")
                    else:
                        return Recuperar_clave.Notificacion(request=request,step=3,Error=valid,user=user)    
            else:
                return Recuperar_clave.Notificacion(request=request,step=2,Error="Código incorrecto.",user=user)
        


            