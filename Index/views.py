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

def redirigir_usuario(request):
    """Función centralizada para redirigir según el tipo de usuario"""
    if not request.user.is_authenticated:
        return redirect('login')
    
    if request.user.is_staff:
        return redirect('admin_dashboard')
    # Aquí puedes añadir más roles según necesites
    # elif request.user.es_cliente:
    #     return redirect('cliente_dashboard')
    else:
        return redirect('dashboard_default')

class Login(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirigir_usuario(request)
        return render(request, 'index.html')

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
                'message': 'Credenciales incorrectas'
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