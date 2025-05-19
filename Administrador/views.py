from django.shortcuts import render,redirect
from django.utils.html import escape
from django.views import View
from django.contrib.auth.models import User
from . import models as Admin_models
from Api import models as Api_models
from Api import utils
from Index import views as Index_views
from Index import correo
from django.http import HttpRequest
import re
import uuid
import secrets
import string
import random
from django.utils import timezone
from Lista_negra import models as Lista_Negra_models
from Api import models as Api_models
# Create your views here.
from django.views import View
from django.shortcuts import render, redirect
from django.db.models import Count
from django.utils.safestring import mark_safe
import json

from django.utils.timezone import now
from django.db.models.functions import TruncMonth
from dateutil.relativedelta import relativedelta
import calendar

class Admin_Dashboard(View):
    def get(self, request):
        if request.user.is_authenticated and request.user.is_staff:
            urls = Lista_Negra_models.URL_Maliciosa.objects.all()
            accesos_denegados = Lista_Negra_models.Acceso_Denegado.objects.all()
            sd = Api_models.Credencial.objects.filter(tipo_sistema='Sistema de detección')
            sm = Api_models.Credencial.objects.filter(tipo_sistema='Sistema de monitoreo')

            # === Labels ===
            metodo_labels = {
                'ENGAÑO': 'Phishing',
                'TECNICO': 'Malware/Exploits',
                'EVASION': 'Evación'
            }
            impacto_labels = {
                'GRAVE': 'Grave',
                'MODERADO': 'Moderado',
                'LEVE': 'Leve'
            }

            # === Amenazas por tipo ===
            cyber_threats_data = [{'name': label, 'value': 0} for label in metodo_labels.values()]
            cyber_threats_qs = Lista_Negra_models.URL_Maliciosa.objects.values('metodo').annotate(total=Count('id'))
            metodo_map = {metodo_labels.get(entry['metodo'], 'Otro'): entry['total'] for entry in cyber_threats_qs if entry['metodo']}
            for item in cyber_threats_data:
                item['value'] = metodo_map.get(item['name'], 0)

            # === Impacto legal ===
            legal_impact_data = [{'name': label, 'value': 0} for label in impacto_labels.values()]
            impacto_qs = Lista_Negra_models.URL_Maliciosa.objects.values('impacto_legal').annotate(total=Count('id'))
            impacto_map = {impacto_labels.get(entry['impacto_legal'], 'Desconocido'): entry['total'] for entry in impacto_qs if entry['impacto_legal']}
            for item in legal_impact_data:
                item['value'] = impacto_map.get(item['name'], 0)

            # === Meses ===
            today = now().replace(day=1)
            months = [today - relativedelta(months=i) for i in reversed(range(7))]

            # === Evidencias ===
            evidencias = Lista_Negra_models.Evidencia.objects.filter(
                fecha_actualizacion__gte=months[0]
            ).annotate(month=TruncMonth('fecha_actualizacion')) \
             .values('month') \
             .annotate(count=Count('id')) \
             .order_by('month')
            evidencia_dict = {e['month'].date(): e['count'] for e in evidencias}
            detecciones_data = [
                {
                    'name': mes.strftime('%b'),
                    'Detecciones': evidencia_dict.get(mes.date(), 0)
                } for mes in months
            ]

            # === Accesos por mes ===
            denegados = Lista_Negra_models.Acceso_Denegado.objects.filter(
                fecha__gte=months[0]
            ).annotate(month=TruncMonth('fecha')) \
             .values('month') \
             .annotate(count=Count('id')) \
             .order_by('month')
            permitidos = Lista_Negra_models.Acceso_Allowed.objects.filter(
                fecha__gte=months[0]
            ).annotate(month=TruncMonth('fecha')) \
             .values('month') \
             .annotate(count=Count('id')) \
             .order_by('month')

            denegados_dict = {d['month'].date(): d['count'] for d in denegados}
            permitidos_dict = {p['month'].date(): p['count'] for p in permitidos}

            accesos_data = [
                {
                    'name': mes.strftime('%b'),
                    'Bloqueadas': denegados_dict.get(mes.date(), 0),
                    'Permitidas': permitidos_dict.get(mes.date(), 0)
                } for mes in months
            ]

            return render(request, 'dashboard/admin/home.html', {
                'total_urls': len(urls),
                'total_intentos_acceso': len(accesos_denegados),
                'sd': len(sd),
                'sm': len(sm),
                'cyber_threats_data': mark_safe(json.dumps(cyber_threats_data)),
                'legal_impact_data': mark_safe(json.dumps(legal_impact_data)),
                'detecciones_data': mark_safe(json.dumps(detecciones_data)),
                'accesos_data': mark_safe(json.dumps(accesos_data)),
            })
        else:
            return redirect('login')

    def post(self,request):
        if request.user.is_authenticated and request.user.is_staff:
            pass
        else:
            return redirect('login')


class Entidades(View):
    @staticmethod
    def Notificacion(request,Error=None,Success=None):
        if request.user.is_authenticated and request.user.is_staff:
            return render(request, 'dashboard/admin/entidades/entidades.html',{
                'Error':Error,"Success":Success,'back':request.POST,
                'entidades':Admin_models.Entidad.objects.all(),
            })
        return Index_views.redirigir_usuario(request)

    def get(self, request:HttpRequest):
        if request.user.is_authenticated and request.user.is_staff:
            return render(request, 'dashboard/admin/entidades/entidades.html',{
                'entidades':Admin_models.Entidad.objects.all(),
            })
        return Index_views.redirigir_usuario(request)

    def post(self, request):
        if request.user.is_authenticated and request.user.is_staff:
            return Entidades.Notificacion(request)
        return Index_views.redirigir_usuario(request)
    

class Nueva_Entidad(View):
    @staticmethod
    def Notificacion(request,Error=None,Success=None):
        if request.user.is_authenticated and request.user.is_staff:
            return render(request, 'dashboard/admin/entidades/nueva_entidad.html',{
                'Error':Error,"Success":Success,'back':request.POST,
            })
        return Index_views.redirigir_usuario(request)

    def get(self,request):
        if request.user.is_authenticated and request.user.is_staff:
            return render(request, 'dashboard/admin/entidades/nueva_entidad.html',{})
        return Index_views.redirigir_usuario(request)

    def post(self, request):
        if request.user.is_authenticated and request.user.is_staff:

            datos_limpios, status = self.validar_y_limpiar_datos_entidad(request_post=request.POST)
            if status != 'OK':
                return Nueva_Entidad.Notificacion(request=request,Error=status)
            

            
            username = datos_limpios.get('username')
            password = self.generar_contrasena_segura()



            userid = User(username=username)
            userid.set_password(password)
            userid.save()

            new_entidad = Admin_models.Entidad(userid=userid,
                                                nombre_entidad = datos_limpios.get('nombre_entidad'),
                                                tipo_entidad = datos_limpios.get('tipo_entidad'),
                                                direccion_fiscal = datos_limpios.get('direccion_fiscal'),
                                                telefono_entidad = datos_limpios.get('telefono_entidad'),
                                                email_institucional = datos_limpios.get('email_institucional'),
                                                sitio_web = datos_limpios.get('sitio_web'),
                                                sector_economico = datos_limpios.get('sector_economico'),
                                                nombre_responsable = datos_limpios.get('nombre_responsable'),
                                                cargo_puesto =  datos_limpios.get('cargo_puesto'),
                                                tipo_documento_identidad = datos_limpios.get('tipo_documento_identidad'),
                                                numero_documento = datos_limpios.get('numero_documento'),
                                                email_responsable = datos_limpios.get('email_responsable'),
                                                telefono_responsable = datos_limpios.get('telefono_responsable'),
                                                direccion_responsable = datos_limpios.get('direccion_responsable'))
            new_entidad.save()
            Asunto = "Registro Exitoso en CyBlack"
            Mensaje = f"""
Estimado/a {datos_limpios.get('nombre_responsable')},

Nos complace informarle que su entidad, {datos_limpios.get('nombre_entidad')}, ha sido registrada exitosamente en CyBlack, el sistema centralizado para el almacenamiento y monitoreo de direcciones URL maliciosas.

Credenciales de acceso:
🔹 Usuario: {username}
🔹 Contraseña temporal: {password} 


Enlace de acceso: https://cyblack.example.com/

Recomendaciones de seguridad:
Cambie su contraseña inmediatamente después de iniciar sesión.

Active la autenticación en dos pasos (2FA) para añadir una capa adicional de seguridad a su cuenta.

No comparta sus credenciales y asegúrese de almacenarlas en un lugar seguro.

Soporte técnico:
Si tiene problemas para acceder al sistema o necesita asistencia, no dude en contactarnos a:
📧 soporte@cyblack.example.com
📞 [+XX XXX XXX XXXX]

Atentamente,
Equipo de Seguridad CyBlack
"""
            correo.enviar_correo(email=datos_limpios.get('email_responsable'),Asunto=Asunto,s=Mensaje)

            return Entidades.Notificacion(request,Success="Entidad registrada correctamente.")
            
        return Index_views.redirigir_usuario(request)

    
    


    def validar_y_limpiar_datos_entidad(self, request_post):
        """
        Valida y limpia los datos de entrada para prevenir inyección de código malicioso.
        Verifica que los campos únicos no estén repetidos en la base de datos.
        Todos los campos son requeridos excepto sitio_web.
        
        Args:
            request_post (dict): Diccionario con los datos POST del request
            
        Returns:
            tuple: (dict, str) 
                - dict: Diccionario con los datos validados y limpios (vacío si hay errores)
                - str: 'OK' si todo está bien, o string con todos los errores encontrados
        """
        # Tipos predefinidos
        tipos_entidades = ('Empresa Privada', 'Organización sin fines de lucro', 'Institución Pública')
        tipos_documentos_identidad = ('Carnet de Identidad', 'Pasaporte')
        
        # Expresiones regulares para validación
        regex_nombre = r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s\-\.,]{2,100}$'
        regex_direccion = r'^[a-zA-Z0-9áéíóúÁÉÍÓÚñÑ\s\-\.,#/()°ºª;:]{5,500}$'
        regex_telefono = r'^[\+\-\s0-9]{7,20}$'
        regex_email = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        regex_sitio_web = r'^(http:\/\/|https:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
        regex_numero_documento = r'^[a-zA-Z0-9\-]{5,20}$'
        regex_username = r'^[a-zA-Z0-9_]{4,30}$'
        
        # Diccionario para almacenar los datos limpios
        datos_limpios = {}
        errores = []
        
        # Función auxiliar para verificar campos requeridos
        def verificar_requerido(valor, nombre_campo):
            if valor is None or valor.strip() == '':
                errores.append(f"El campo '{nombre_campo}' es requerido")
                return False
            return True
        
        # Función auxiliar para verificar campos únicos
        def verificar_unico(modelo, campo, valor, mensaje_error):
            if modelo.objects.filter(**{campo: valor}).exists():
                errores.append(mensaje_error)
                return False
            return True
        
        # Validación de datos de la entidad
        # 1. Nombre de entidad (requerido)
        nombre_entidad = request_post.get('nombre_entidad', '').strip()
        if verificar_requerido(nombre_entidad, 'nombre_entidad'):
            if not re.match(regex_nombre, nombre_entidad):
                errores.append("El nombre de la entidad no es válido (solo letras, espacios y algunos caracteres especiales, 2-100 caracteres)")
            else:
                if not verificar_unico(Admin_models.Entidad, 'nombre_entidad', nombre_entidad, "El nombre de la entidad ya está registrado."):
                    pass  # El error ya fue añadido
                else:
                    datos_limpios['nombre_entidad'] = escape(nombre_entidad)
        
        # 2. Tipo de entidad (requerido)
        tipo_entidad = request_post.get('tipo_entidad', '').strip()
        if verificar_requerido(tipo_entidad, 'tipo_entidad'):
            if tipo_entidad not in tipos_entidades:
                errores.append(f"El tipo de entidad seleccionado no es válido. Opciones válidas: {', '.join(tipos_entidades)}")
            else:
                datos_limpios['tipo_entidad'] = escape(tipo_entidad)
        
        # 3. Dirección fiscal (requerido y único)
        direccion_fiscal = request_post.get('direccion_fiscal', '').strip()
        if verificar_requerido(direccion_fiscal, 'direccion_fiscal'):
            if not re.match(regex_direccion, direccion_fiscal):
                errores.append("La dirección fiscal no es válida (5-200 caracteres alfanuméricos y algunos caracteres especiales)")
            else:
                if not verificar_unico(Admin_models.Entidad, 'direccion_fiscal', direccion_fiscal, "La dirección fiscal ya está registrada"):
                    pass  # El error ya fue añadido
                else:
                    datos_limpios['direccion_fiscal'] = escape(direccion_fiscal)
        
        # 4. Teléfono de entidad (requerido y único)
        telefono_entidad = request_post.get('telefono_entidad', '').strip()
        if verificar_requerido(telefono_entidad, 'telefono_entidad'):
            if not re.match(regex_telefono, telefono_entidad):
                errores.append("El teléfono de la entidad no es válido (7-20 dígitos, puede incluir +, - o espacios)")
            else:
                if not verificar_unico(Admin_models.Entidad, 'telefono_entidad', telefono_entidad, "El teléfono de entidad ya está registrado"):
                    pass
                else:
                    datos_limpios['telefono_entidad'] = escape(telefono_entidad)
        
        # 5. Email institucional (requerido y único)
        email_institucional = request_post.get('email_institucional', '').strip().lower()
        if verificar_requerido(email_institucional, 'email_institucional'):
            if not re.match(regex_email, email_institucional):
                errores.append("El email institucional no es válido (debe tener formato ejemplo@dominio.com)")
            else:
                if not verificar_unico(Admin_models.Entidad, 'email_institucional', email_institucional, "El email institucional ya está registrado"):
                    pass
                else:
                    datos_limpios['email_institucional'] = escape(email_institucional)
        
        # 6. Sitio web (OPCIONAL y único)
        sitio_web = request_post.get('sitio_web', '').strip()
        if sitio_web:  # Solo validar si tiene contenido
            if not re.match(regex_sitio_web, sitio_web):
                errores.append("El sitio web no es válido (debe comenzar con http:// o https:// y ser una URL válida)")
            else:
                # Normalizar URL
                if not sitio_web.lower().startswith(('http://', 'https://')):
                    sitio_web = 'http://' + sitio_web
                if not verificar_unico(Admin_models.Entidad, 'sitio_web', sitio_web, "El sitio web ya está registrado"):
                    pass
                else:
                    datos_limpios['sitio_web'] = escape(sitio_web)
        else:
            datos_limpios['sitio_web'] = ''
        
        # 7. Sector económico (requerido)
        sector_economico = request_post.get('sector_economico', '').strip()
        if verificar_requerido(sector_economico, 'sector_economico'):
            if not re.match(regex_nombre, sector_economico):
                errores.append("El sector económico no es válido (solo letras, espacios y algunos caracteres especiales, 2-100 caracteres)")
            else:
                datos_limpios['sector_economico'] = escape(sector_economico)
        
        # Validación de datos del responsable
        # 1. Nombre del responsable (requerido y único)
        nombre_responsable = request_post.get('nombre_responsable', '').strip()
        if verificar_requerido(nombre_responsable, 'nombre_responsable'):
            if not re.match(regex_nombre, nombre_responsable):
                errores.append("El nombre del responsable no es válido (solo letras, espacios y algunos caracteres especiales, 2-100 caracteres)")
            else:
                if not verificar_unico(Admin_models.Entidad, 'nombre_responsable', nombre_responsable, "El nombre del responsable ya está registrado"):
                    pass
                else:
                    datos_limpios['nombre_responsable'] = escape(nombre_responsable)
        
        # 2. Cargo/puesto (requerido)
        cargo_puesto = request_post.get('cargo_puesto', '').strip()
        if verificar_requerido(cargo_puesto, 'cargo_puesto'):
            if not re.match(regex_nombre, cargo_puesto):
                errores.append("El cargo/puesto no es válido (solo letras, espacios y algunos caracteres especiales, 2-100 caracteres)")
            else:
                datos_limpios['cargo_puesto'] = escape(cargo_puesto)
        
        # 3. Tipo de documento de identidad (requerido)
        tipo_documento_identidad = request_post.get('tipo_documento_identidad', '').strip()
        if verificar_requerido(tipo_documento_identidad, 'tipo_documento_identidad'):
            if tipo_documento_identidad not in tipos_documentos_identidad:
                errores.append(f"El tipo de documento de identidad no es válido. Opciones válidas: {', '.join(tipos_documentos_identidad)}")
            else:
                datos_limpios['tipo_documento_identidad'] = escape(tipo_documento_identidad)
        
        # 4. Número de documento (requerido)
        numero_documento = request_post.get('numero_documento', '').strip()
        if verificar_requerido(numero_documento, 'numero_documento'):
            if not re.match(regex_numero_documento, numero_documento):
                errores.append("El número de documento no es válido (5-20 caracteres alfanuméricos o guiones)")
            else:
                datos_limpios['numero_documento'] = escape(numero_documento)
        
        # 5. Email del responsable (requerido y único)
        email_responsable = request_post.get('email_responsable', '').strip().lower()
        if verificar_requerido(email_responsable, 'email_responsable'):
            if not re.match(regex_email, email_responsable):
                errores.append("El email del responsable no es válido (debe tener formato ejemplo@dominio.com)")
            else:
                if not verificar_unico(Admin_models.Entidad, 'email_responsable', email_responsable, "El email del responsable ya está registrado"):
                    pass
                else:
                    datos_limpios['email_responsable'] = escape(email_responsable)
        
        # 6. Teléfono del responsable (requerido y único)
        telefono_responsable = request_post.get('telefono_responsable', '').strip()
        if verificar_requerido(telefono_responsable, 'telefono_responsable'):
            if not re.match(regex_telefono, telefono_responsable):
                errores.append("El teléfono del responsable no es válido (7-20 dígitos, puede incluir +, - o espacios)")
            else:
                if not verificar_unico(Admin_models.Entidad, 'telefono_responsable', telefono_responsable, "El teléfono del responsable ya está registrado"):
                    pass
                else:
                    datos_limpios['telefono_responsable'] = escape(telefono_responsable)
        
        # 7. Dirección del responsable (requerido y único)
        direccion_responsable = request_post.get('direccion_responsable', '').strip()
        if verificar_requerido(direccion_responsable, 'direccion_responsable'):
            if not re.match(regex_direccion, direccion_responsable):
                errores.append("La dirección del responsable no es válida (5-200 caracteres alfanuméricos y algunos caracteres especiales)")
            else:
                if not verificar_unico(Admin_models.Entidad, 'direccion_responsable', direccion_responsable, "La dirección del responsable ya está registrada"):
                    pass
                else:
                    datos_limpios['direccion_responsable'] = escape(direccion_responsable)
        
        # 8. Username (requerido) - Verificar con el modelo User
        username = request_post.get('username', '').strip()
        if verificar_requerido(username, 'username'):
            if not re.match(regex_username, username):
                errores.append("El nombre de usuario no es válido (solo letras, números y guiones bajos, 4-30 caracteres)")
            else:
                
                if User.objects.filter(username=username).exists():
                    errores.append("El nombre de usuario ya está registrado")
                else:
                    datos_limpios['username'] = escape(username)
        
        if errores:
            # Unir todos los errores con saltos de línea y viñetas
            mensaje_errores = "Se encontraron los siguientes errores: " + ". ".join(f"{error}" for error in errores)
            return {}, mensaje_errores
        else:
            return datos_limpios, "OK"
        

        

    def generar_contrasena_segura(self, longitud_minima=24):
        """
        Genera una contraseña aleatoria segura con al menos 24 caracteres.
        
        La contraseña incluirá:
        - Letras mayúsculas
        - Letras minúsculas
        - Dígitos
        - Caracteres especiales
        - No tendrá caracteres ambiguos como l, I, 1, O, 0, etc.
        
        Args:
            longitud_minima (int): Longitud mínima de la contraseña (default 24)
            
        Returns:
            str: Contraseña generada
        """
        # Definimos los conjuntos de caracteres
        minusculas = 'abcdefghjkmnpqrstuvwxyz'  # Excluimos l, i, o
        mayusculas = 'ABCDEFGHJKLMNPQRSTUVWXYZ'  # Excluimos I, O
        digitos = '23456789'  # Excluimos 0, 1
        especiales = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        # Combinamos todos los caracteres posibles
        todos_caracteres = minusculas + mayusculas + digitos + especiales
        
        # Aseguramos al menos un carácter de cada tipo
        contrasena = [
            secrets.choice(minusculas),
            secrets.choice(mayusculas),
            secrets.choice(digitos),
            secrets.choice(especiales)
        ]
        
        # Completamos hasta alcanzar la longitud mínima
        contrasena.extend(secrets.choice(todos_caracteres) for _ in range(longitud_minima - 4))
        
        # Mezclamos los caracteres para mayor aleatoriedad
        random.shuffle(contrasena)
        
        # Convertimos a string
        return ''.join(contrasena)
    


class Editar_Entidad(View):
    @staticmethod
    def Notificacion(request,id,Error=None,Success=None):
        entidad = None
        if request.user.is_authenticated and request.user.is_staff:
            try:
                entidad = Admin_models.Entidad.objects.get(id=id)
            except Exception as e:
                return Entidades.Notificacion(request=request,Error="Entidad no encontrada")
            return render(request,'dashboard/admin/entidades/editar_entidad.html',{
                'back':request.POST,'entidad_id':entidad.id,
                'Error':Error,'Success':Success,
            })
        return Index_views.redirigir_usuario(request)


    def get(self,request,id):
        entidad = None
        if request.user.is_authenticated and request.user.is_staff:
            try:
                entidad = Admin_models.Entidad.objects.get(id=id)
            except Exception as e:
                return Entidades.Notificacion(request=request,Error="Entidad no encontrada")
            return render(request,'dashboard/admin/entidades/editar_entidad.html',{
                'entidad':entidad,'entidad_id':entidad.id
            })
        return Index_views.redirigir_usuario(request)


    def post(self,request,id):
        if request.user.is_authenticated and request.user.is_staff:
            entidad_existente = None
            try:
                entidad_existente = Admin_models.Entidad.objects.get(id=id)
            except Exception as e:
                return Entidades.Notificacion(request=request,Error='Entidad no encontrada.')

            datos_limpios, status = self.validar_y_limpiar_datos_entidad(request_post=request.POST,entidad=entidad_existente)
            
            print(datos_limpios.get('nombre_entidad'))
            print(type(datos_limpios.get('nombre_entidad')))

            if status != 'OK':
                return Editar_Entidad.Notificacion(request=request,id=id,Error=status)
            

            
            username = datos_limpios.get('username')
            entidad_existente.userid.username = username
            entidad_existente.userid.save()



            entidad_existente.nombre_entidad = str(datos_limpios.get('nombre_entidad'))
            entidad_existente.tipo_entidad = str(datos_limpios.get('tipo_entidad'))
            entidad_existente.direccion_fiscal = str(datos_limpios.get('direccion_fiscal'))
            entidad_existente.telefono_entidad = str(datos_limpios.get('telefono_entidad'))
            entidad_existente.email_institucional = str(datos_limpios.get('email_institucional'))
            entidad_existente.sitio_web = str(datos_limpios.get('sitio_web'))
            entidad_existente.sector_economico = str(datos_limpios.get('sector_economico'))
            entidad_existente.nombre_responsable = str(datos_limpios.get('nombre_responsable'))
            entidad_existente.cargo_puesto =  str(datos_limpios.get('cargo_puesto'))
            entidad_existente.tipo_documento_identidad = str(datos_limpios.get('tipo_documento_identidad'))
            entidad_existente.numero_documento = str(datos_limpios.get('numero_documento'))
            entidad_existente.email_responsable = str(datos_limpios.get('email_responsable'))
            entidad_existente.telefono_responsable = str(datos_limpios.get('telefono_responsable'))
            entidad_existente.direccion_responsable = str(datos_limpios.get('direccion_responsable'))
            entidad_existente.save()
    
            return Entidades.Notificacion(request,Success="Entidad actualizada correctamente.")
            
        return Index_views.redirigir_usuario(request)

    

    def validar_y_limpiar_datos_entidad(self, request_post,entidad:Admin_models.Entidad):
        """
        Valida y limpia los datos de entrada para prevenir inyección de código malicioso.
        Verifica que los campos únicos no estén repetidos en la base de datos.
        Todos los campos son requeridos excepto sitio_web.
        
        Args:
            request_post (dict): Diccionario con los datos POST del request
            
        Returns:
            tuple: (dict, str) 
                - dict: Diccionario con los datos validados y limpios (vacío si hay errores)
                - str: 'OK' si todo está bien, o string con todos los errores encontrados
        """
        # Tipos predefinidos
        tipos_entidades = ('Empresa Privada', 'Organización sin fines de lucro', 'Institución Pública')
        tipos_documentos_identidad = ('Carnet de Identidad', 'Pasaporte')
        
        # Expresiones regulares para validación
        regex_nombre = r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s\-\.,]{2,100}$'
        regex_direccion = r'^[a-zA-Z0-9áéíóúÁÉÍÓÚñÑ\s\-\.,#/()°ºª;:]{5,500}$'
        regex_telefono = r'^[\+\-\s0-9]{7,20}$'
        regex_email = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        regex_sitio_web = r'^(http:\/\/|https:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
        regex_numero_documento = r'^[a-zA-Z0-9\-]{5,20}$'
        regex_username = r'^[a-zA-Z0-9_]{4,30}$'
        
        # Diccionario para almacenar los datos limpios
        datos_limpios = {}
        errores = []
        
        # Función auxiliar para verificar campos requeridos
        def verificar_requerido(valor, nombre_campo):
            if valor is None or valor.strip() == '':
                errores.append(f"El campo '{nombre_campo}' es requerido")
                return False
            return True
        
        # Función auxiliar para verificar campos únicos
        def verificar_unico(modelo, campo, valor, mensaje_error):
            if modelo.objects.filter(**{campo: valor}).exists():
                errores.append(mensaje_error)
                return False
            return True
        
        # Validación de datos de la entidad
        # 1. Nombre de entidad (requerido)
        nombre_entidad = request_post.get('nombre_entidad', '').strip()
        if verificar_requerido(nombre_entidad, 'nombre_entidad'):
            if nombre_entidad != entidad.nombre_entidad:
                if not re.match(regex_nombre, nombre_entidad):
                    errores.append("El nombre de la entidad no es válido (solo letras, espacios y algunos caracteres especiales, 2-100 caracteres)")
            
                if not verificar_unico(Admin_models.Entidad, 'nombre_entidad', nombre_entidad, "El nombre de la entidad ya está registrado."):
                    pass  # El error ya fue añadido
            
            datos_limpios['nombre_entidad'] = escape(nombre_entidad)
        
        # 2. Tipo de entidad (requerido)
        tipo_entidad = request_post.get('tipo_entidad', '').strip()
        if verificar_requerido(tipo_entidad, 'tipo_entidad'):
            if tipo_entidad not in tipos_entidades:
                errores.append(f"El tipo de entidad seleccionado no es válido. Opciones válidas: {', '.join(tipos_entidades)}")
            else:
                datos_limpios['tipo_entidad'] = escape(tipo_entidad)
        
        # 3. Dirección fiscal (requerido y único)
        direccion_fiscal = request_post.get('direccion_fiscal', '').strip()
        if verificar_requerido(direccion_fiscal, 'direccion_fiscal'):
            if not re.match(regex_direccion, direccion_fiscal):
                errores.append("La dirección fiscal no es válida (5-200 caracteres alfanuméricos y algunos caracteres especiales)")
            else:
                if direccion_fiscal != entidad.direccion_fiscal:
                    if not verificar_unico(Admin_models.Entidad, 'direccion_fiscal', direccion_fiscal, "La dirección fiscal ya está registrada"):
                        pass  # El error ya fue añadido
                datos_limpios['direccion_fiscal'] = escape(direccion_fiscal)
            
        # 4. Teléfono de entidad (requerido y único)
        telefono_entidad = request_post.get('telefono_entidad', '').strip()
        if verificar_requerido(telefono_entidad, 'telefono_entidad'):
            if not re.match(regex_telefono, telefono_entidad):
                errores.append("El teléfono de la entidad no es válido (7-20 dígitos, puede incluir +, - o espacios)")
            else:
                if telefono_entidad != entidad.telefono_entidad:
                    if not verificar_unico(Admin_models.Entidad, 'telefono_entidad', telefono_entidad, "El teléfono de entidad ya está registrado"):
                        pass
                datos_limpios['telefono_entidad'] = escape(telefono_entidad)
        
        # 5. Email institucional (requerido y único)
        email_institucional = request_post.get('email_institucional', '').strip().lower()
        if verificar_requerido(email_institucional, 'email_institucional'):
            if not re.match(regex_email, email_institucional):
                errores.append("El email institucional no es válido (debe tener formato ejemplo@dominio.com)")
            else:
                if email_institucional != entidad.email_institucional:
                    if not verificar_unico(Admin_models.Entidad, 'email_institucional', email_institucional, "El email institucional ya está registrado"):
                        pass
                datos_limpios['email_institucional'] = escape(email_institucional)
        
        # 6. Sitio web (OPCIONAL y único)
        sitio_web = request_post.get('sitio_web', '').strip()
        if sitio_web:  # Solo validar si tiene contenido
            if not re.match(regex_sitio_web, sitio_web):
                errores.append("El sitio web no es válido (debe comenzar con http:// o https:// y ser una URL válida)")
            else:
                if sitio_web != entidad.sitio_web:
                    # Normalizar URL
                    if not sitio_web.lower().startswith(('http://', 'https://')):
                        sitio_web = 'http://' + sitio_web
                    if not verificar_unico(Admin_models.Entidad, 'sitio_web', sitio_web, "El sitio web ya está registrado"):
                        pass    
                datos_limpios['sitio_web'] = escape(sitio_web)
        else:
            datos_limpios['sitio_web'] = ''
        
        # 7. Sector económico (requerido)
        sector_economico = request_post.get('sector_economico', '').strip()
        if verificar_requerido(sector_economico, 'sector_economico'):
            if not re.match(regex_nombre, sector_economico):
                errores.append("El sector económico no es válido (solo letras, espacios y algunos caracteres especiales, 2-100 caracteres)")
            else:
                datos_limpios['sector_economico'] = escape(sector_economico)
        
        # Validación de datos del responsable
        # 1. Nombre del responsable (requerido y único)
        nombre_responsable = request_post.get('nombre_responsable', '').strip()
        if verificar_requerido(nombre_responsable, 'nombre_responsable'):
            if not re.match(regex_nombre, nombre_responsable):
                errores.append("El nombre del responsable no es válido (solo letras, espacios y algunos caracteres especiales, 2-100 caracteres)")
            else:
                if nombre_responsable != entidad.nombre_responsable:
                    if not verificar_unico(Admin_models.Entidad, 'nombre_responsable', nombre_responsable, "El nombre del responsable ya está registrado"):
                        pass
                datos_limpios['nombre_responsable'] = escape(nombre_responsable)
        
        # 2. Cargo/puesto (requerido)
        cargo_puesto = request_post.get('cargo_puesto', '').strip()
        if verificar_requerido(cargo_puesto, 'cargo_puesto'):
            if not re.match(regex_nombre, cargo_puesto):
                errores.append("El cargo/puesto no es válido (solo letras, espacios y algunos caracteres especiales, 2-100 caracteres)")
            else:
                datos_limpios['cargo_puesto'] = escape(cargo_puesto)
        
        # 3. Tipo de documento de identidad (requerido)
        tipo_documento_identidad = request_post.get('tipo_documento_identidad', '').strip()
        if verificar_requerido(tipo_documento_identidad, 'tipo_documento_identidad'):
            if tipo_documento_identidad not in tipos_documentos_identidad:
                errores.append(f"El tipo de documento de identidad no es válido. Opciones válidas: {', '.join(tipos_documentos_identidad)}")
            else:
                datos_limpios['tipo_documento_identidad'] = escape(tipo_documento_identidad)
        
        # 4. Número de documento (requerido)
        numero_documento = request_post.get('numero_documento', '').strip()
        if verificar_requerido(numero_documento, 'numero_documento'):
            if not re.match(regex_numero_documento, numero_documento):
                errores.append("El número de documento no es válido (5-20 caracteres alfanuméricos o guiones)")
            else:
                datos_limpios['numero_documento'] = escape(numero_documento)
        
        # 5. Email del responsable (requerido y único)
        email_responsable = request_post.get('email_responsable', '').strip().lower()
        if verificar_requerido(email_responsable, 'email_responsable'):
            if not re.match(regex_email, email_responsable):
                errores.append("El email del responsable no es válido (debe tener formato ejemplo@dominio.com)")
            else:
                if email_responsable != entidad.email_responsable:
                    if not verificar_unico(Admin_models.Entidad, 'email_responsable', email_responsable, "El email del responsable ya está registrado"):
                        pass
                datos_limpios['email_responsable'] = escape(email_responsable)
        
        # 6. Teléfono del responsable (requerido y único)
        telefono_responsable = request_post.get('telefono_responsable', '').strip()
        if verificar_requerido(telefono_responsable, 'telefono_responsable'):
            if not re.match(regex_telefono, telefono_responsable):
                errores.append("El teléfono del responsable no es válido (7-20 dígitos, puede incluir +, - o espacios)")
            else:
                if telefono_responsable != entidad.telefono_responsable:
                    if not verificar_unico(Admin_models.Entidad, 'telefono_responsable', telefono_responsable, "El teléfono del responsable ya está registrado"):
                        pass
                datos_limpios['telefono_responsable'] = escape(telefono_responsable)
        

        # 7. Dirección del responsable (requerido y único)
        direccion_responsable = request_post.get('direccion_responsable', '').strip()
        if verificar_requerido(direccion_responsable, 'direccion_responsable'):
            if not re.match(regex_direccion, direccion_responsable):
                errores.append("La dirección del responsable no es válida (5-200 caracteres alfanuméricos y algunos caracteres especiales)")
            else:
                if direccion_responsable != entidad.direccion_responsable:
                    if not verificar_unico(Admin_models.Entidad, 'direccion_responsable', direccion_responsable, "La dirección del responsable ya está registrada"):
                        pass
                datos_limpios['direccion_responsable'] = escape(direccion_responsable)
        

        # 8. Username (requerido) - Verificar con el modelo User
        username = request_post.get('username', '').strip()
        if verificar_requerido(username, 'username'):
            if not re.match(regex_username, username):
                errores.append("El nombre de usuario no es válido (solo letras, números y guiones bajos, 4-30 caracteres)")
            else:
                if username != entidad.userid.username:
                    if User.objects.filter(username=username).exists():
                        errores.append("El nombre de usuario ya está registrado")
                datos_limpios['username'] = escape(username)
        
        if errores:
            # Unir todos los errores con saltos de línea y viñetas
            mensaje_errores = "Se encontraron los siguientes errores: " + ". ".join(f"{error}" for error in errores)
            return datos_limpios, mensaje_errores
        else:
            return datos_limpios, "OK"
    

class Eliminar_Entidad(View):
    def get(self,request):
        if request.user.is_authenticated and request.user.is_staff:
            return Entidades.Notificacion(request)
        return Index_views.redirigir_usuario(request)

    def post(self,request):
        if request.user.is_authenticated and request.user.is_staff:
            id = escape(request.POST.get('entidad_id'))
            try:
                entidad = Admin_models.Entidad.objects.get(id=id)
                entidad.userid.delete()
                entidad.delete()
                return Entidades.Notificacion(request=request,Success='La entidad ha sido eliminada correctamente.')
            except Exception as e:
                return Entidades.Notificacion(request=request,Error='La entidad no esta registrada.')
            
            
        return Index_views.redirigir_usuario(request)







class Credenciales(View):
    @staticmethod
    def Notificacion(request,Error=None,Success=None):
        if request.user.is_authenticated and request.user.is_staff:
            entidades = Admin_models.Entidad.objects.all().order_by('nombre_entidad')
            credenciales = Api_models.Credencial.objects.all()
            entidades_disponibles = []
            credenciales_disponibles = []
            for e in entidades:
                l = credenciales.filter(entidad_id=e)
                if len(l) < 2:
                    entidades_disponibles.append(e)
                aux = {}
                for ca in l:
                    if ca.tipo_sistema == Api_models.tipo_sistema[0]:
                        aux['deteccion'] = ca
                    elif ca.tipo_sistema == Api_models.tipo_sistema[1]:
                        aux['monitoreo'] = ca
                if(len(l)>0):
                    credenciales_disponibles.append({'entidad':e,'credencial':aux})
            
            return render(request,'dashboard/admin/credenciales/credenciales.html',{
                'entidades_disponibles':entidades_disponibles,
                'credenciales_disponibles':credenciales_disponibles,'tipo_sistema':Api_models.tipo_sistema,
                'Error':Error,'Success':Success,
            })
        return Index_views.redirigir_usuario(request)


    def get(self,request):
        if request.user.is_authenticated and request.user.is_staff:
            entidades = Admin_models.Entidad.objects.all().order_by('nombre_entidad')
            credenciales = Api_models.Credencial.objects.all()
            entidades_disponibles = []
            credenciales_disponibles = []
            for e in entidades:
                l = credenciales.filter(entidad_id=e)
                if len(l) < 2:
                    entidades_disponibles.append(e)
                aux = {}
                for ca in l:
                    if ca.tipo_sistema == Api_models.tipo_sistema[0]:
                        aux['deteccion'] = ca
                    elif ca.tipo_sistema == Api_models.tipo_sistema[1]:
                        aux['monitoreo'] = ca
                if(len(l)>0):
                    credenciales_disponibles.append({'entidad':e,'credencial':aux})
            
            return render(request,'dashboard/admin/credenciales/credenciales.html',{
                'entidades_disponibles':entidades_disponibles,
                'credenciales_disponibles':credenciales_disponibles,'tipo_sistema':Api_models.tipo_sistema,
            })
        return Index_views.redirigir_usuario(request)

    def post(self,request):
        if request.user.is_authenticated and request.user.is_staff:
            return Credenciales.Notificacion(request)
        return Index_views.redirigir_usuario(request)

class Nueva_Credencial(View):
    def get(self,request):
        if request.user.is_authenticated and request.user.is_staff:
            return Credenciales.Notificacion(request)
        return Index_views.redirigir_usuario(request)

    def post(self,request):
        if request.user.is_authenticated and request.user.is_staff:
            entidad_id = escape(request.POST.get('entidad_id'))
            tipo_sistema = escape(request.POST.get('tipo_sistema'))
            credencial, status = utils.crear_credencial(entidad_id=entidad_id,tipo_sistema=tipo_sistema)
            if status!='OK':
                return Credenciales.Notificacion(request=request,Error=status)
            
            Asunto = f"Registro exitoso de credenciales para {credencial.tipo_sistema}"
            mensaje = f"""
Estimado/a {credencial.entidad_id.nombre_responsable},  

Le informamos que las credenciales de acceso para el {credencial.tipo_sistema} han sido registradas exitosamente en nuestra plataforma.  

**Detalles de la configuración:**  
- Entidad: {credencial.entidad_id.nombre_entidad}
- Sistema: {credencial.tipo_sistema}
- UID: {credencial.uid}
- Fecha de registro: {timezone.localtime(credencial.ultima_actualizacion).strftime("%d/%m/%Y %H:%M:%S")}  

**Archivos adjuntos:**  
1. `api_key.pem`: Clave pública para autenticación.  
2. `secret_key.pem`: Clave privada para firma digital (manéjela con confidencialidad).  


**Soporte:**  
- 📄 Documentación de la API: [Enlace a la documentación]  
- 📞 Soporte técnico: [Teléfono] o [Correo de soporte]  

Quedamos atentos a cualquier consulta.  

            """
            correo.enviar_correo_con_claves(email=credencial.entidad_id.email_responsable,asunto=Asunto,mensaje=mensaje,clave_publica_str=credencial.public_key,clave_privada_str=credencial.private_key)
            return Credenciales.Notificacion(request=request,Success='Credencial registrada correctamente.')
        return Index_views.redirigir_usuario(request)


class Renovar_credencial(View):
    def get(self,request):
        if request.user.is_authenticated and request.user.is_staff:
            return Credenciales.Notificacion(request)
        return Index_views.redirigir_usuario(request)
    
    def post(self,request):
        if request.user.is_authenticated and request.user.is_staff:
            uid = escape(request.POST.get('uid'))
            credencial = None
            try:
                credencial = Api_models.Credencial.objects.get(uid=uid)
            except Exception as e:
                return Credenciales.Notificacion(request=request,Error='La credencial no esta registrada.')
            
            entidad_id = credencial.entidad_id.id
            tipo_sistema = credencial.tipo_sistema

            credencial, status = utils.crear_credencial(entidad_id=entidad_id,tipo_sistema=tipo_sistema,update=True)
            if status!='OK':
                return Credenciales.Notificacion(request=request,Error=status)
            

            Asunto = f"Renovación exitosa de credenciales para {credencial.tipo_sistema}"
            mensaje = f"""
Estimado/a {credencial.entidad_id.nombre_responsable},  

Le informamos que las credenciales de acceso para el {credencial.tipo_sistema} han sido renovadas exitosamente en nuestra plataforma.  

**Detalles de la configuración:**  
- Entidad:  {credencial.entidad_id.nombre_entidad} 
- Sistema: {credencial.tipo_sistema}  
- Fecha de renovacion: {timezone.localtime(credencial.ultima_actualizacion).strftime("%d/%m/%Y %H:%M:%S")} 
- UID: {credencial.uid} 

**Archivos adjuntos:**  
1. `clave_publica.pem`: Clave pública para autenticación.  
2. `clave_privada.pem`: Clave privada para firma digital (manéjela con confidencialidad).  


**Soporte:**  
- 📄 Documentación de la API: [Enlace a la documentación]  
- 📞 Soporte técnico: [Teléfono] o [Correo de soporte]  

Quedamos atentos a cualquier consulta.  

            """
            correo.enviar_correo_con_claves(email=credencial.entidad_id.email_responsable,asunto=Asunto,mensaje=mensaje,clave_publica_str=credencial.public_key,clave_privada_str=credencial.private_key)

            return Credenciales.Notificacion(request=request,Success='Credencial renovada correctamente.')
        return Index_views.redirigir_usuario(request)


class Revocar_credencial(View):
    def get(self,request):
        if request.user.is_authenticated and request.user.is_staff:
            return Credenciales.Notificacion(request)
        return Index_views.redirigir_usuario(request)
    
    def post(self,request):
        if request.user.is_authenticated and request.user.is_staff:
            uid = escape(request.POST.get('uid'))
            credencial = None
            try:
                credencial = Api_models.Credencial.objects.get(uid=uid)
            except Exception as e:
                return Credenciales.Notificacion(request=request,Error='La credencial no esta registrada.')
            

            Asunto = f"Credencial Revocada: Acceso a CyBlack ha sido inhabilitado"
            Mensaje = f"""
Estimado/a {credencial.entidad_id.nombre_responsable},  

Por motivos de seguridad, hemos procedido a revocar permanentemente las credenciales de acceso para:  

▸ Sistema: {credencial.tipo_sistema}  
▸ Entidad: {credencial.entidad_id.nombre_entidad} 
▸ UID: {credencial.uid}

**Esta acción es irreversible** y significa que:  
• Las claves anteriores ya no funcionarán  
• Todo acceso usando estas credenciales será denegado  
 

**Acción requerida:**  
1. Elimine inmediatamente las copias locales de estas credenciales.
2. Notifique a su equipo técnico sobre esta revocación.
3. [Opcional] Solicite nuevas credenciales mediante [proceso/documentación]  

Para validar esta acción o reportar inconvenientes:  
📞 [Teléfono de soporte] | ✉️ [Email de seguridad]  

Atentamente,  
Equipo de Seguridad  
Cyblack
"""
            correo.enviar_correo(email=credencial.entidad_id.email_responsable,Asunto=Asunto,s=Mensaje)
            credencial.delete()
            return Credenciales.Notificacion(request=request,Success='Credencial revocada correctamente.')
        return Index_views.redirigir_usuario(request)






class Estadistica(View):
    def get(self,request):
        return Index_views.redirigir_usuario(request=request)


    def post(self, request):
        access = False
        if request.user.is_staff:
            access = True
        entidad = Admin_models.Entidad.objects.filter(userid=request.user)
        if entidad.exists():
            access = True

        if access == True:
            try:
                entidad = Admin_models.Entidad.objects.get(id=request.POST.get('entidad_id'))
                
                # === Labels ===
                metodo_labels = {
                    'ENGAÑO': 'Phishing',
                    'TECNICO': 'Malware/Exploits',
                    'EVASION': 'Evación'
                }
                impacto_labels = {
                    'GRAVE': 'Grave',
                    'MODERADO': 'Moderado',
                    'LEVE': 'Leve'
                }

                # Obtener URLs relacionadas con la entidad (a través de evidencias o accesos)
                urls_con_evidencias = Lista_Negra_models.URL_Maliciosa.objects.filter(
                    evidencias__entidad=entidad
                ).distinct()

                urls_con_accesos_denegados = Lista_Negra_models.URL_Maliciosa.objects.filter(
                    accesos_denegados__entidad=entidad
                ).distinct()

                # Combinar todos los IDs de URLs relevantes
                url_ids = set(urls_con_evidencias.values_list('id', flat=True)) | \
                        set(urls_con_accesos_denegados.values_list('id', flat=True))

                # === Amenazas por tipo ===
                cyber_threats_data = [{'name': label, 'value': 0} for label in metodo_labels.values()]
                cyber_threats_qs = Lista_Negra_models.URL_Maliciosa.objects.filter(
                    id__in=url_ids
                ).values('metodo').annotate(total=Count('id'))
                
                metodo_map = {metodo_labels.get(entry['metodo'], 'Otro'): entry['total'] for entry in cyber_threats_qs if entry['metodo']}
                for item in cyber_threats_data:
                    item['value'] = metodo_map.get(item['name'], 0)

                # === Impacto legal ===
                legal_impact_data = [{'name': label, 'value': 0} for label in impacto_labels.values()]
                impacto_qs = Lista_Negra_models.URL_Maliciosa.objects.filter(
                    id__in=url_ids
                ).values('impacto_legal').annotate(total=Count('id'))
                
                impacto_map = {impacto_labels.get(entry['impacto_legal'], 'Desconocido'): entry['total'] for entry in impacto_qs if entry['impacto_legal']}
                for item in legal_impact_data:
                    item['value'] = impacto_map.get(item['name'], 0)

                # === Meses ===
                today = now().replace(day=1)
                months = [today - relativedelta(months=i) for i in reversed(range(7))]

                # === Evidencias ===
                evidencias = Lista_Negra_models.Evidencia.objects.filter(
                    entidad=entidad,
                    fecha_actualizacion__gte=months[0]
                ).annotate(month=TruncMonth('fecha_actualizacion')) \
                .values('month') \
                .annotate(count=Count('id')) \
                .order_by('month')
                
                evidencia_dict = {e['month'].date(): e['count'] for e in evidencias}
                detecciones_data = [
                    {
                        'name': mes.strftime('%b'),
                        'Detecciones': evidencia_dict.get(mes.date(), 0)
                    } for mes in months
                ]

                # === Accesos por mes ===
                denegados = Lista_Negra_models.Acceso_Denegado.objects.filter(
                    entidad=entidad,
                    fecha__gte=months[0]
                ).annotate(month=TruncMonth('fecha')) \
                .values('month') \
                .annotate(count=Count('id')) \
                .order_by('month')
                
                permitidos = Lista_Negra_models.Acceso_Allowed.objects.filter(
                    entidad=entidad,
                    fecha__gte=months[0]
                ).annotate(month=TruncMonth('fecha')) \
                .values('month') \
                .annotate(count=Count('id')) \
                .order_by('month')

                denegados_dict = {d['month'].date(): d['count'] for d in denegados}
                permitidos_dict = {p['month'].date(): p['count'] for p in permitidos}

                accesos_data = [
                    {
                        'name': mes.strftime('%b'),
                        'Bloqueadas': denegados_dict.get(mes.date(), 0),
                        'Permitidas': permitidos_dict.get(mes.date(), 0)
                    } for mes in months
                ]

                return render(request, 'dashboard/Estadistica/estadistica.html', {
                    'entidad': entidad,
                    'cyber_threats_data': mark_safe(json.dumps(cyber_threats_data)),
                    'legal_impact_data': mark_safe(json.dumps(legal_impact_data)),
                    'detecciones_data': mark_safe(json.dumps(detecciones_data)),
                    'accesos_data': mark_safe(json.dumps(accesos_data)),
                    'base':"dashboard/admin/base_admin.html" if request.user.is_staff else "dashboard/entidad/entidad_base.html"
                })
            except Exception as e:
                print(f"Error: {str(e)}")  # Para depuración
                return Index_views.redirigir_usuario(request)


        return Index_views.redirigir_usuario(request)