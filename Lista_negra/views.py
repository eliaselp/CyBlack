from django.shortcuts import render
from django.views import View
from Index import views as Index_views
from Lista_negra import models as Lista_negra_models
import json
from django.db.models import Q
from django.core.exceptions import ValidationError
from urllib.parse import urlparse, urlunparse, ParseResult
from django.http import JsonResponse,HttpRequest
import re
from django.core.serializers.json import DjangoJSONEncoder
from django.db import transaction
from datetime import datetime


# Create your views here.
class Lista_negra(View):
    @staticmethod
    @transaction.atomic
    def Notificacion(request:HttpRequest,Error=None,Success=None):
        if request.user.is_authenticated:
            # Obtener todas las URLs con sus relaciones
            urls = Lista_negra_models.URL_Maliciosa.objects.all().prefetch_related(
                'evidencias',
                'accesos_denegados',
                'accesos_denegados__entidad'
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
                
                for acceso in url.accesos_denegados.all():
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
                'urls_data_json': urls_data_json,
                'Error':Error,'Success':Success,
                'base':"dashboard/admin/base_admin.html" if request.user.is_staff else "dashboard/entidad/entidad_base.html"
            })
        return Index_views.redirigir_usuario(request=request)

    @transaction.atomic
    def get(self, request):
        if request.user.is_authenticated:
            # Obtener todas las URLs con sus relaciones
            urls = Lista_negra_models.URL_Maliciosa.objects.all().prefetch_related(
                'evidencias',
                'accesos_denegados',
                'accesos_denegados__entidad'
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
                
                for acceso in url.accesos_denegados.all():
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
                'urls_data_json': urls_data_json,
                'base':"dashboard/admin/base_admin.html" if request.user.is_staff else "dashboard/entidad/entidad_base.html"
            })
        return Index_views.redirigir_usuario(request=request)


    def post(self,request):
        if request.user.is_authenticated:
            return Lista_negra.Notification(request=request)
        return Index_views.redirigir_usuario(request=request)
    




@transaction.atomic
def aplicar_filtros(request):
    if request.method == 'POST':
        if request.user.is_authenticated:
            # Obtener todos los parámetros de filtro del POST
            busqueda_general = request.POST.get('busquedaGeneral', '').strip()
            protocolo = request.POST.get('protocolo', '')
            puerto = request.POST.get('puerto', '')
            objetivo = request.POST.get('objetivo', '')
            metodo = request.POST.get('metodo', '')
            impacto = request.POST.get('impacto', '')
            metodo_deteccion = request.POST.get('metodo_deteccion', '')
            entidad = request.POST.get('entidad', '')
            fecha_inicio = request.POST.get('fecha_inicio', '')
            fecha_fin = request.POST.get('fecha_fin', '')

            # Construir el queryset base con prefetch_related
            urls_query = Lista_negra_models.URL_Maliciosa.objects.all().prefetch_related(
                'evidencias',
                'accesos_denegados',
                'accesos_denegados__entidad'
            )

            # Aplicar filtros
            if busqueda_general:
                urls_query = urls_query.filter(
                    Q(url__icontains=busqueda_general) |
                    Q(ip__icontains=busqueda_general) |
                    Q(descripcion__icontains=busqueda_general)
                )

            if protocolo:
                urls_query = urls_query.filter(protocolo=protocolo)

            if puerto:
                urls_query = urls_query.filter(puerto=puerto)

            if objetivo:
                urls_query = urls_query.filter(objetivo=objetivo)

            if metodo:
                urls_query = urls_query.filter(metodo=metodo)

            if impacto:
                urls_query = urls_query.filter(impacto_legal=impacto)

            # Filtros relacionados con evidencias
            if metodo_deteccion or entidad:
                evidencias_filter = Q()
                if metodo_deteccion:
                    evidencias_filter &= Q(evidencias__metodo_deteccion=metodo_deteccion)
                if entidad:
                    evidencias_filter &= Q(evidencias__entidad_id=entidad)
                
                urls_query = urls_query.filter(evidencias_filter).distinct()

            # Filtros por fecha
            if fecha_inicio and fecha_fin:
                try:
                    fecha_inicio_dt = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
                    fecha_fin_dt = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
                    urls_query = urls_query.filter(
                        fecha_deteccion__date__range=[fecha_inicio_dt, fecha_fin_dt]
                    )
                except ValueError:
                    pass

            # Obtener todas las entidades únicas para el filtro (igual que en la vista original)
            from Administrador.models import Entidad
            entidades = Entidad.objects.all().distinct()
            entidades_choices = [(entidad.id, entidad.nombre_entidad) for entidad in entidades]
            
            # Obtener tipos de entidad únicos para el filtro
            tipos_entidad = Entidad.objects.values_list('tipo_entidad', flat=True).distinct()
            tipos_entidad_choices = [(tipo, tipo) for tipo in tipos_entidad if tipo]
            
            # Preparar datos para el modal (igual que en la vista original)
            urls_data = []
            for url in urls_query:
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
                
                for acceso in url.accesos_denegados.all():
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
                    'protocolo': url.protocolo,
                    'protocolo_display': f"{url.get_protocolo_display()} (Puerto: {url.puerto})",
                    'puerto': url.puerto,
                    'impacto': url.impacto_legal,
                    'impacto_display': url.get_impacto_legal_display(),
                    'descripcion': url.descripcion or 'Sin descripción',
                    'evidencias': evidencias,
                    'accesos': accesos,
                    'objetivo': url.objetivo,
                    'objetivo_display': url.get_objetivo_display(),
                    'metodo': url.metodo,
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
                'urls': urls_query,
                'urls_data_json': urls_data_json,
                'base': "dashboard/admin/base_admin.html" if request.user.is_staff else "dashboard/entidad/entidad_base.html",
                'filtros_aplicados': True,
                'filtros': {
                    'busquedaGeneral': busqueda_general,
                    'protocolo': protocolo,
                    'puerto': puerto,
                    'objetivo': objetivo,
                    'metodo': metodo,
                    'impacto': impacto,
                    'metodo_deteccion': metodo_deteccion,
                    'entidad': entidad,
                    'fecha_inicio': fecha_inicio,
                    'fecha_fin': fecha_fin
                }
            })
        return Index_views.redirigir_usuario(request=request)
    return Lista_negra.Notificacion(request=request)





##############################################################################################################
##############################################################################################################
##############################################################################################################





def normalizar_url(url_input: str, protocolo: str = 'http', puerto: str = None) -> str:
    """
    Normaliza una URL asegurando protocolo, limpieza de credenciales y dominio en minúsculas.

    Args:
        url_input (str): URL a normalizar.
        protocolo (str): Protocolo deseado ('http' o 'https').
        puerto (str|int): Puerto deseado (opcional).

    Returns:
        str: URL normalizada.

    Raises:
        ValueError: Si la URL no es válida.
    """
    if not isinstance(url_input, str) or not url_input.strip():
        raise ValueError("URL vacía o inválida")

    url_input = url_input.strip()

    # Normalizar protocolo
    protocolo = protocolo.lower()
    if protocolo not in {'http', 'https'}:
        protocolo = 'http'

    # Agregar protocolo si falta
    if '://' not in url_input:
        url_input = f'{protocolo}://{url_input}'

    try:
        parsed = urlparse(url_input)
    except Exception as e:
        raise ValueError(f"Error al parsear la URL: {str(e)}")

    # Limpiar netloc de credenciales
    hostname = parsed.hostname or ''
    port = str(puerto) if puerto else (str(parsed.port) if parsed.port else '')

    # Reconstruir netloc (sin credenciales)
    netloc = hostname.lower()
    if port:
        netloc += f':{port}'

    # Construir nuevo ParseResult con componentes originales
    normalized = ParseResult(
        scheme=protocolo,
        netloc=netloc,
        path=parsed.path or '',
        params=parsed.params or '',
        query=parsed.query or '',
        fragment=parsed.fragment or ''
    )

    url_final = urlunparse(normalized)

    # Validación final
    if not normalized.scheme or not normalized.netloc:
        raise ValueError("URL no válida tras normalización")

    return url_final



@transaction.atomic
def CrearURLEvidenciaView(FILES, data, entidad):
    try:
        # =============================================
        # SECCIÓN 1: VALIDACIONES Y PARSEOS
        # =============================================

        get = data.get  # Optimización: cachear el método
        try:
            puerto = int(get('puerto'))
            if not (1 <= puerto <= 65535):
                raise ValidationError("Puerto fuera de rango (1-65535)")
        except (TypeError, ValueError):
            raise ValidationError("Puerto inválido o ausente")

        protocolo = get('protocolo')
        raw_url = get('url')
        if not raw_url or not protocolo:
            raise ValidationError("URL y protocolo son obligatorios")

        try:
            url = normalizar_url(raw_url, protocolo, puerto)
        except Exception as e:
            raise ValidationError(f"Error al normalizar URL: {str(e)}")

        metodo_deteccion = get('metodo_deteccion')
        if not metodo_deteccion:
            raise ValidationError("Método de detección obligatorio")

        # Procesar datos técnicos
        datos_tecnicos_raw = get('datos_tecnicos', {})
        if isinstance(datos_tecnicos_raw, str):
            try:
                datos_tecnicos = json.loads(datos_tecnicos_raw)
            except json.JSONDecodeError:
                raise ValidationError("Datos técnicos no tienen formato JSON válido")
        elif isinstance(datos_tecnicos_raw, dict):
            datos_tecnicos = datos_tecnicos_raw
        else:
            raise ValidationError("Formato inválido para datos técnicos")

        # Buscar si ya existe la URL y la evidencia
        url_existente = Lista_negra_models.URL_Maliciosa.objects.filter(url=url).first()
        evidencia_existente = (
            Lista_negra_models.Evidencia.objects.filter(
                url_maliciosa=url_existente, entidad=entidad
            ).first()
            if url_existente else None
        )

        # =============================================
        # SECCIÓN 2: OPERACIONES DE BD (ATÓMICAS)
        # =============================================

        with transaction.atomic():
            if evidencia_existente:
                evidencia_existente.delete()

            if not url_existente:
                url_maliciosa = Lista_negra_models.URL_Maliciosa.objects.create(
                    protocolo=protocolo,
                    puerto=puerto,
                    url=url,
                    ip=get('ip'),
                    objetivo=get('objetivo'),
                    metodo=get('metodo'),
                    impacto_legal=get('impacto_legal'),
                    descripcion=get('descripcion_url'),
                )
            else:
                url_maliciosa = url_existente

            evidencia = Lista_negra_models.Evidencia(
                metodo_deteccion=metodo_deteccion,
                descripcion=get('descripcion_evidencia'),
                entidad=entidad,
                url_maliciosa=url_maliciosa,
                datos_tecnicos=json.dumps(datos_tecnicos),
            )

            archivo = FILES.get('archivo_evidencia')
            if archivo:
                evidencia.archivo = archivo

            evidencia.save()

        # =============================================
        # RESPUESTA
        # =============================================
        return JsonResponse({
            'status': 'success',
            'message': 'URL maliciosa y evidencia registradas correctamente',
            'url_id': url_maliciosa.id,
            'evidencia_id': evidencia.id,
        })

    except ValidationError as ve:
        return JsonResponse({'status': 'error', 'message': str(ve)}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f'Error interno: {str(e)}'}, status=500)



@transaction.atomic
def Query_access(data, entidad):
    try:
        # =============================================
        # SECCIÓN 1: VALIDACIONES Y PARSEOS
        # =============================================
        get = data.get
        url = get('url')
        
        print("==>> ",url)
        
        # Buscar si ya existe la URL
        url_existente = Lista_negra_models.URL_Maliciosa.objects.filter(url=url)
        
        # =============================================
        # SECCIÓN 2: OPERACIONES DE BD (ATÓMICAS)
        # =============================================

        with transaction.atomic():
            if url_existente.exists():
                acceso_denegado = Lista_negra_models.Acceso_Denegado.objects.create(
                    url=url_existente.first(),
                    entidad=entidad
                )
                return JsonResponse({
                    'status': 'success',
                    'message': 'Acceso denegado, la URL es maliciosa',
                })
            else:
                acceso_denegado = Lista_negra_models.Acceso_Allowed.objects.create(
                    entidad=entidad
                )
                return JsonResponse({
                    'status': 'success',
                    'message': 'Acceso permitido',
                })
            
    except ValidationError as ve:
        return JsonResponse({'status': 'error', 'message': str(ve)}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f'Error interno: {str(e)}'}, status=500)
