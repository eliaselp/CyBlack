from django.shortcuts import render
from django.views import View
from Index import views as Index_views
from Lista_negra import models as Lista_negra_models

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
    
    def get(self,request):
        if request.user.is_authenticated:
            return render(request,'dashboard/lista_negra/lista_negra.html',{
                'PROTOCOLO_CHOICES': Lista_negra_models.PROTOCOLO_CHOICES,
                'OBJETIVO_CHOICES': Lista_negra_models.OBJETIVO_CHOICES,
                'METODO_CHOICES': Lista_negra_models.METODO_CHOICES,
                'IMPACTO_LEGAL_CHOICES': Lista_negra_models.IMPACTO_LEGAL_CHOICES,
                'METODO_DETECCION_CHOICES': Lista_negra_models.Evidencia.METODO_DETECCION_CHOICES,
            })
        return Index_views.redirigir_usuario(request=request)
    
    def post(self,request):
        if request.user.is_authenticated:
            return Lista_negra.Notification(request=request)
        return Index_views.redirigir_usuario(request=request)
    







from django.db.models import Q
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




from django.core.exceptions import ValidationError
from urllib.parse import urlparse, urlunparse
import json
from django.http import JsonResponse

def normalizar_url(self, url_input, protocolo, puerto):
    """
    Normaliza la URL para asegurar formato consistente:
    1. Asegura que tenga el protocolo correcto
    2. Maneja correctamente el puerto
    3. Elimina componentes innecesarios
    """
    if not url_input:
        return ""
    
    # Si la URL ya incluye protocolo, lo parseamos
    parsed = urlparse(url_input)
    
    # Determinar el protocolo a usar (priorizando el seleccionado en el formulario)
    scheme = protocolo.lower()
    
    # Manejar casos donde la URL viene sin protocolo
    if not parsed.scheme:
        netloc = parsed.path.split('/')[0] if parsed.path else ''
        path = '/' + '/'.join(parsed.path.split('/')[1:]) if parsed.path else ''
        parsed = parsed._replace(scheme=scheme, netloc=netloc, path=path)
    
    # Reconstruir la URL con el protocolo correcto
    if parsed.netloc:
        # Si ya tiene puerto en la URL, lo reemplazamos con el del formulario
        netloc = parsed.netloc.split(':')[0]
        netloc = f"{netloc}:{puerto}" if puerto else netloc
        parsed = parsed._replace(netloc=netloc)
    else:
        # Si no tiene netloc, asumimos que el primer segmento del path es el dominio
        parts = parsed.path.split('/')
        if parts and parts[0]:
            netloc = f"{parts[0]}:{puerto}" if puerto else parts[0]
            path = '/' + '/'.join(parts[1:]) if len(parts) > 1 else '/'
            parsed = parsed._replace(netloc=netloc, path=path)
    
    # Asegurar que el scheme (protocolo) sea el seleccionado
    parsed = parsed._replace(scheme=scheme)
    
    # Limpiar parámetros, fragmentos y autenticación
    parsed = parsed._replace(params='', query='', fragment='', username='', password='')
    
    # Construir URL normalizada
    normalized_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))
    
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
    datos_tecnicos = data.get('datos_tecnicos', '{}')
    try:
        # Validar que sea JSON válido
        json.loads(datos_tecnicos)
        evidencia_data['datos_tecnicos'] = datos_tecnicos
    except json.JSONDecodeError:
        raise ValidationError("Los datos técnicos deben tener formato JSON válido")
    
    
    # Procesar archivo si existe
    if 'archivo_evidencia' in FILES:
        evidencia.archivo = FILES['archivo_evidencia']
    

    # Crear instancia de URL_Maliciosa
    url_maliciosa = Lista_negra_models.URL_Maliciosa(**url_data)
    url_maliciosa.save()
    
    evidencia_data['url_maliciosa'] = url_maliciosa,

    # Crear instancia de Evidencia
    evidencia = Lista_negra_models.Evidencia(**evidencia_data)
    
    evidencia.save()
    
    return JsonResponse({
        'status': 'success',
        'message': 'URL maliciosa y evidencia registradas correctamente',
    })