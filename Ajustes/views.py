from django.shortcuts import render
from django.views import View
from django.http import HttpRequest
from Index import views as Index_views
from django.utils.html import escape
from django.contrib.auth import authenticate,login
from django.conf import settings

from django.contrib.sessions.models import Session
from django.utils import timezone
from user_agents import parse

import re
# Create your views here.

class Ajustes(View):
    @staticmethod
    def Notificacion(request:HttpRequest,Error=None,Success=None):
        if request.user.is_authenticated:
            back=None
            sesiones = Ajustes.obtener_sesiones_activas(request)
            if Error and request.POST:
                back = request.POST
            return render(request,'dashboard/Ajustes/ajustes.html',{
                'Error':Error,'Success':Success,'back':back,
                'sesiones':sesiones,'sesion_actual':request.session.session_key
            })
        else:
            return Index_views.redirigir_usuario(request=request)


    def get(self,request:HttpRequest):
        if request.user.is_authenticated:
            sesiones = Ajustes.obtener_sesiones_activas(request)
            return render(request,'dashboard/Ajustes/ajustes.html',{
                'sesiones':sesiones,'sesion_actual':request.session.session_key
            })
        else:
            return Index_views.redirigir_usuario(request=request)


    def post(self,request:HttpRequest):
        if request.user.is_authenticated:
            return Ajustes.Notificacion(request=request)
        else:
            return Index_views.redirigir_usuario(request=request)



    @staticmethod
    def obtener_sesiones_activas(request):
        """
        Obtiene todas las sesiones activas con detalles del dispositivo.
        
        Args:
            request: HttpRequest (para obtener la sesión actual)
        
        Returns:
            list: Lista de diccionarios con información de cada sesión activa.
                Ejemplo: [{
                    'ip': '192.168.1.1',
                    'navegador': 'Chrome 119',
                    'so': 'Windows 10',
                    'ultima_actividad': '2023-11-15 10:30:00',
                    'es_actual': True/False
                }]
        """
        # Obtener todas las sesiones no expiradas
        sesiones = Session.objects.filter(expire_date__gte=timezone.now())
        
        sesiones_activas = []
        
        for sesion in sesiones:
            try:
                # Decodificar datos de sesión
                datos_sesion = sesion.get_decoded()
                # Verificar que la sesión pertenece al usuario actual
                if '_auth_user_id' not in datos_sesion or str(datos_sesion['_auth_user_id']) != str(request.user.pk):
                    continue
                # Obtener user_agent y IP almacenados (asumiendo que los guardas al login)
                user_agent = datos_sesion.get('user_agent', '')
                ip = datos_sesion.get('ip', 'Desconocida')
                
                # Parsear User-Agent
                ua = parse(user_agent)
                
                sesiones_activas.append({
                    'session_key': sesion.session_key,
                    'ip': ip,
                    'navegador': f"{ua.browser.family} {ua.browser.version_string}",
                    'so': f"{ua.os.family} {ua.os.version_string}",
                    'ultima_actividad': sesion.expire_date.strftime('%Y-%m-%d %H:%M:%S'),
                    'es_actual': (sesion.session_key == request.session.session_key)
                })
            except Exception as e:
                continue
        
        return sesiones_activas



class Cambiar_contrasenna(View):
    def get(self,request:HttpRequest):
        if request.user.is_authenticated:
            return Ajustes.Notificacion(request=request)
        else:
            return Index_views.redirigir_usuario(request=request)

    def post(self,request:HttpRequest):
        if request.user.is_authenticated:
            password_actual = escape(request.POST.get('password_actual'))
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            if request.user.check_password(password_actual):
                v,m = Cambiar_contrasenna.validar_contraseña(contraseña1=new_password,contraseña2=confirm_password)
                if v == False:
                    return Ajustes.Notificacion(request=request,Error=m)
                confirm_password = escape(confirm_password)
                request.user.set_password(confirm_password)
                request.user.save()
                user = authenticate(request, username=request.user.username, password=confirm_password)
                login(request, user)

                # IMPORTANTE: Configura la sesión correctamente
                request.session.set_expiry(settings.SESSION_COOKIE_AGE)
                request.session.save()
                
                return Ajustes.Notificacion(request=request,Success="Contraseña actualizada correctamente.")
            return Ajustes.Notificacion(request=request,Error="Contraseña actual incorrecta.")
        else:
            return Index_views.redirigir_usuario(request=request)


    @staticmethod
    def validar_contraseña(contraseña1, contraseña2):
        """
        Valida si dos contraseñas son iguales y cumplen con estándares de seguridad.
        
        Args:
            contraseña1 (str): Primera contraseña.
            contraseña2 (str): Segunda contraseña (para confirmación).
        
        Returns:
            tuple: (bool, str) 
                - bool: True si es válida y coincide, False en caso contrario.
                - str: Mensaje detallando el error (si hay alguno).
        """
        
        # Verificar igualdad
        if contraseña1 != contraseña2:
            return False, "Las contraseñas no coinciden."
        
        # Verificar longitud mínima
        if len(contraseña1) < 8:
            return False, "La contraseña debe tener al menos 8 caracteres."
        
        # Verificar complejidad con expresiones regulares
        requisitos = [
            (r'[A-Z]', "Debe contener al menos una letra mayúscula."),
            (r'[a-z]', "Debe contener al menos una letra minúscula."),
            (r'[0-9]', "Debe contener al menos un número."),
            (r'[!@#$%^&*(),.?":{}|<>]', "Debe contener al menos un carácter especial.")
        ]
        
        for regex, mensaje in requisitos:
            if not re.search(regex, contraseña1):
                return False, mensaje
        
        # Si pasa todas las validaciones
        return True, "Contraseña válida."




def cerrar_sesion_remota(request:HttpRequest):
    if request.POST and request.user.is_authenticated:
        session_key = request.POST.get('session_key')
        if session_key != request.session.session_key:
            Session.objects.filter(session_key=session_key).delete()
            return Ajustes.Notificacion(request=request,Success="Sesion cerrada correctamente.")
        return Ajustes.Notificacion(request=request,Error='Error, no se puede cerrar la sesion actual.')
    else:
        return Ajustes.Notificacion(request=request)
    
def cerrar_todas_las_sesiones(request:HttpRequest):
    if request.POST and request.user.is_authenticated:
        sesiones = Ajustes.obtener_sesiones_activas(request=request)
        i = 0
        for sesion in sesiones:
            if sesion.get('session_key') != request.session.session_key:
                Session.objects.filter(session_key=sesion.get('session_key')).delete()
                i+=1
        if i>0:
            return Ajustes.Notificacion(request=request,Success="Se han cerrado todas las sesiones correctamente")
        else:
            return Ajustes.Notificacion(request=request,Error="No hay sesiones por cerrar.")
    else:
        return Ajustes.Notificacion(request=request)