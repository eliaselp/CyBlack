from django.shortcuts import render
from django.views import View
from Index import views as Index_views
from Lista_negra import models as Lista_negra_models
import json
from django.db.models import Q
from django.core.exceptions import ValidationError
from urllib.parse import urlparse, urlunparse, ParseResult
from django.http import JsonResponse
import re
from django.core.serializers.json import DjangoJSONEncoder


# Create your views here.
class Lista_negra(View):
    @staticmethod
    def Notification(self,request,Error=None,Success=None):
        if request.user.is_authenticated:
            return render(request,'dashboard/lista_negra/lista_negra.html',{
                'Error':Error,'Success':Success,
                'PROTOCOLO_CHOICES': Lista_negra_models.PROTOCOLO_CHOICES,
                'OBJETIVO_CHOICES': Lista_negra_models.OBJETIVO_CHOICES,
                'METODO_CHOICES': Lista_negra_models.METODO_CHOICES,
                'IMPACTO_LEGAL_CHOICES': Lista_negra_models.IMPACTO_LEGAL_CHOICES,
                'METODO_DETECCION_CHOICES': Lista_negra_models.Evidencia.METODO_DETECCION_CHOICES,
            })
        return Index_views.redirigir_usuario(request=request)
    
    def get(self, request):
        if request.user.is_authenticated:
            # Obtener todas las URLs con sus relaciones
            urls = Lista_negra_models.URL_Maliciosa.objects.all().prefetch_related(
                'evidencias',
                'accesos',
                'accesos__entidad'
            )
            
            # Obtener todas las entidades únicas para el filtro
            from Administrador.models import Entidad
            entidades = Entidad.objects.all().distinct()
            entidades_choices = [(entidad.id, entidad.nombre_entidad) for entidad in entidades]
            
            # Obtener tipos de entidad únicos para el filtro
            tipos_entidad = Entidad.objects.values_list('tipo_entidad', flat=True).distinct()
            tipos_entidad_choices = [(tipo, tipo) for tipo in tipos_entidad if tipo]
            
            # Preparar datos para el modal
            urls_data = []
            for url in urls:
                # Obtener evidencias relacionadas
                evidencias = []
                for evidencia in url.evidencias.all():
                    # Manejar datos_tecnicos (puede ser dict o str)
                    datos_tecnicos = evidencia.datos_tecnicos
                    if isinstance(datos_tecnicos, str):
                        try:
                            datos_tecnicos = json.loads(datos_tecnicos)
                        except json.JSONDecodeError:
                            datos_tecnicos = {"error": "Formato JSON inválido en datos técnicos"}
                    
                    evidencias.append({
                        'id': evidencia.id,
                        'institucion': evidencia.entidad.nombre_entidad if evidencia.entidad else "Anónima",
                        'institucion_id': evidencia.entidad.id if evidencia.entidad else None,
                        'metodo': evidencia.get_metodo_deteccion_display(),
                        'metodo_value': evidencia.metodo_deteccion,
                        'fecha': evidencia.fecha_creacion.strftime('%Y-%m-%d %H:%M'),
                        'descripcion': evidencia.descripcion,
                        'archivo': evidencia.archivo.url if evidencia.archivo else None,
                        'nombre_archivo': evidencia.archivo.name.split('/')[-1] if evidencia.archivo else None,
                        'estado': "Confirmada",
                        'datos_tecnicos': datos_tecnicos if datos_tecnicos else {}
                    })
                
                # Obtener accesos por institución
                accesos = []
                acceso_counts = {}
                
                for acceso in url.accesos.all():
                    entidad_nombre = acceso.entidad.nombre_entidad if acceso.entidad else "Anónima"
                    if entidad_nombre not in acceso_counts:
                        acceso_counts[entidad_nombre] = {
                            'count': 0,
                            'ultimo_intento': acceso.fecha,
                            'tipo': acceso.entidad.tipo_entidad if acceso.entidad else "Desconocido",
                            'entidad_id': acceso.entidad.id if acceso.entidad else None
                        }
                    acceso_counts[entidad_nombre]['count'] += 1
                    if acceso.fecha > acceso_counts[entidad_nombre]['ultimo_intento']:
                        acceso_counts[entidad_nombre]['ultimo_intento'] = acceso.fecha
                
                for entidad, data in acceso_counts.items():
                    accesos.append({
                        'institucion': entidad,
                        'institucion_id': data['entidad_id'],
                        'tipo': data['tipo'],
                        'intentos': data['count'],
                        'ultimo_intento': data['ultimo_intento'].strftime('%Y-%m-%d %H:%M')
                    })
                
                urls_data.append({
                    'id': url.id,
                    'url': url.url,
                    'ip': url.ip,
                    'protocolo': url.protocolo,  # Valor original para filtrado
                    'protocolo_display': f"{url.get_protocolo_display()} (Puerto: {url.puerto})",
                    'puerto': url.puerto,
                    'impacto': url.impacto_legal,  # Valor original para filtrado
                    'impacto_display': url.get_impacto_legal_display(),
                    'descripcion': url.descripcion or 'Sin descripción',
                    'evidencias': evidencias,
                    'accesos': accesos,
                    'objetivo': url.objetivo,  # Valor original para filtrado
                    'objetivo_display': url.get_objetivo_display(),
                    'metodo': url.metodo,  # Valor original para filtrado
                    'metodo_display': url.get_metodo_display(),
                    'fecha_deteccion': url.fecha_deteccion.strftime('%Y-%m-%d %H:%M'),
                    'fecha_deteccion_iso': url.fecha_deteccion.isoformat(),
                    'ultimo_acceso': url.ultima_acceso.strftime('%Y-%m-%d %H:%M'),
                    'ultimo_acceso_iso': url.ultima_acceso.isoformat(),
                    'total_accesos': url.total_accesos
                })
            
            # Serializar con DjangoJSONEncoder para manejar tipos complejos
            urls_data_json = json.dumps(urls_data, cls=DjangoJSONEncoder)
            
            return render(request, 'dashboard/lista_negra/lista_negra.html', {
                'PROTOCOLO_CHOICES': Lista_negra_models.PROTOCOLO_CHOICES,
                'OBJETIVO_CHOICES': Lista_negra_models.OBJETIVO_CHOICES,
                'METODO_CHOICES': Lista_negra_models.METODO_CHOICES,
                'IMPACTO_LEGAL_CHOICES': Lista_negra_models.IMPACTO_LEGAL_CHOICES,
                'METODO_DETECCION_CHOICES': Lista_negra_models.Evidencia.METODO_DETECCION_CHOICES,
                'ENTIDADES_CHOICES': entidades_choices,
                'TIPOS_ENTIDAD_CHOICES': tipos_entidad_choices,
                'urls': urls,
                'urls_data_json': urls_data_json
            })
        return Index_views.redirigir_usuario(request=request)
    
    def post(self,request):
        if request.user.is_authenticated:
            return Lista_negra.Notification(request=request)
        return Index_views.redirigir_usuario(request=request)
    








def aplicar_filtros(request):
    urls = Lista_negra_models.URL_Maliciosa.objects.all().prefetch_related('evidencias', 'acceso_set__entidad')
    
    # Filtrado
    filters = Q()
    if request.GET.get('q'):
        q = request.GET['q']
        filters &= (
            Q(url__icontains=q) |
            Q(ip__icontains=q) |
            Q(descripcion__icontains=q)
        )
    # Filtros individuales
    filter_fields = {
        'protocolo': 'protocolo',
        'objetivo': 'objetivo',
        'metodo': 'metodo',
        'impacto_legal': 'impacto_legal',
        'metodo_deteccion': 'evidencias__metodo_deteccion'
    }
    
    for param, field in filter_fields.items():
        value = request.GET.get(param)
        if value:
            filters &= Q(**{f'{field}': value})
    
    urls = urls.filter(filters).distinct()

    context = {
        'urls': urls,
        'PROTOCOLO_CHOICES': Lista_negra_models.PROTOCOLO_CHOICES,
        'OBJETIVO_CHOICES': Lista_negra_models.OBJETIVO_CHOICES,
        'METODO_CHOICES': Lista_negra_models.METODO_CHOICES,
        'IMPACTO_LEGAL_CHOICES': Lista_negra_models.IMPACTO_LEGAL_CHOICES,
        'METODO_DETECCION_CHOICES': Lista_negra_models.Evidencia.METODO_DETECCION_CHOICES,
    }
    return render(request, 'dashboard/lista_negra.html', context)



##############################################################################################################
##############################################################################################################
##############################################################################################################




def normalizar_url(url_input: str, protocolo: str = 'http', puerto: str = None) -> str:
    """
    Normaliza una URL manteniendo la mayoría de componentes originales:
    
    1. Asegura el protocolo correcto (http/https en minúsculas)
    2. Convierte el dominio a minúsculas
    3. Mantiene path, queries, fragments y otros componentes exactamente como están
    4. Maneja el puerto según parámetro
    5. Elimina credenciales de autenticación
    
    Args:
        url_input (str): URL a normalizar
        protocolo (str): Protocolo deseado (http/https)
        puerto (str): Puerto deseado (opcional)
    
    Returns:
        str: URL normalizada
    
    Raises:
        ValueError: Si la URL no es válida después de normalización
    """
    if not url_input or not isinstance(url_input, str):
        return ""
    
    # Limpieza inicial de la URL
    url_input = url_input.strip()
    
    # Asegurar que el protocolo sea válido y en minúsculas
    protocolo = protocolo.lower()
    if protocolo not in ('http', 'https'):
        protocolo = 'http'
    
    # Parsear la URL (manejar casos sin protocolo)
    if '://' not in url_input:
        url_input = f'{protocolo}://{url_input}'
    
    try:
        parsed = urlparse(url_input)
    except Exception as e:
        raise ValueError(f"Error al parsear URL: {str(e)}")
    
    # Inicializar netloc con el valor parseado
    netloc = parsed.netloc
    
    # Manejar credenciales (username:password@)
    if parsed.username or parsed.password:
        netloc = netloc.split('@')[-1]  # Elimina la parte de autenticación
    
    # Manejar el puerto
    if puerto:
        # Eliminar puerto existente si lo hay
        netloc = netloc.split(':')[0]
        # Agregar nuevo puerto
        netloc = f"{netloc}:{puerto}"
    
    # Convertir solo el dominio a minúsculas (parte antes del primer : o /)
    domain_part = netloc.split(':')[0].split('/')[0]
    if domain_part:
        netloc = netloc.replace(domain_part, domain_part.lower(), 1)
    
    # Mantener todos los otros componentes exactamente como están
    normalized_components = ParseResult(
        scheme=protocolo.lower(),  # Protocolo en minúsculas
        netloc=netloc,             # Dominio en minúsculas, resto igual
        path=parsed.path,          # Path original exacto
        params=parsed.params,      # Parámetros originales
        query=parsed.query,        # Query string original
        fragment=parsed.fragment   # Fragmento original
    )
    
    # Construir URL normalizada
    normalized_url = urlunparse(normalized_components)
    
    # Validación final de la URL
    if not all([normalized_components.scheme, normalized_components.netloc]):
        raise ValueError("URL no válida después de normalización")
    
    return normalized_url










def CrearURLEvidenciaView(FILES, data):
    # Procesar y validar puerto (ahora obligatorio)
    try:
        puerto = int(data.get('puerto'))
        if not (1 <= puerto <= 65535):
            raise ValidationError("El puerto debe estar entre 1 y 65535")
    except (ValueError, TypeError):
        raise ValidationError("Puerto es obligatorio y debe ser un número válido")

    # Normalizar la URL
    url = normalizar_url(
        data.get('url'),
        data.get('protocolo'),
        puerto
    )
    
    # Procesar datos de URL_Maliciosa
    url_data = {
        'protocolo': data.get('protocolo'),
        'puerto': puerto,
        'url': url,
        'ip': data.get('ip'),
        'objetivo': data.get('objetivo'),
        'metodo': data.get('metodo'),
        'impacto_legal': data.get('impacto_legal'),
        'descripcion': data.get('descripcion_url'),
    }
    
    # Validar campos obligatorios para URL
    if not url_data['url'] or not url_data['protocolo']:
        raise ValidationError("URL y protocolo son campos obligatorios")
    
    # Procesar datos de Evidencia
    evidencia_data = {
        'metodo_deteccion': data.get('metodo_deteccion'),
        'descripcion': data.get('descripcion_evidencia'),
    }
    
    # Validar método de detección (obligatorio)
    if not evidencia_data['metodo_deteccion']:
        raise ValidationError("Método de detección es obligatorio")
    
    # Procesar datos técnicos (JSON)
    datos_tecnicos = data.get('datos_tecnicos', {})
    try:
        if isinstance(datos_tecnicos, str):
            datos_tecnicos = json.loads(datos_tecnicos)
        elif not isinstance(datos_tecnicos, dict):
            raise ValidationError("Los datos técnicos deben ser un JSON válido")
        
        evidencia_data['datos_tecnicos'] = json.dumps(datos_tecnicos)
    except (json.JSONDecodeError, TypeError) as e:
        raise ValidationError(f"Formato inválido para datos técnicos: {str(e)}")
    
    
    url_maliciosa = Lista_negra_models.URL_Maliciosa(**url_data)
    url_maliciosa.save()
    
    # Asignar la URL maliciosa a los datos de evidencia
    evidencia_data['url_maliciosa'] = url_maliciosa

    # Crear instancia de Evidencia
    evidencia = Lista_negra_models.Evidencia(**evidencia_data)
    
    # Procesar archivo si existe - AHORA DESPUÉS de crear la instancia
    if 'archivo_evidencia' in FILES:
        evidencia.archivo = FILES['archivo_evidencia']
    
    # Guardar la evidencia (con o sin archivo)
    evidencia.save()
    print(url_maliciosa,evidencia)
    return JsonResponse({
        'status': 'success',
        'message': 'URL maliciosa y evidencia registradas correctamente',
    })