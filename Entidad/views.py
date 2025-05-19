from django.shortcuts import render
from Index import views as Index_views
from django.http import HttpRequest
# Create your views here.
from django.views import View
from Administrador import models as Admin_models
from Lista_negra import models as Lista_Negra_models


from django.db.models import Count
from dateutil.relativedelta import relativedelta
import json
from django.utils.safestring import mark_safe
from django.utils.timezone import now
from django.db.models.functions import TruncMonth


class Entidad_Dashboard(View):
    @staticmethod
    def Notificacion(request:HttpRequest,Error=None,Success=None):
        if request.user.is_staff:
            return Index_views.redirigir_usuario(request=request)
        
        entidad = Admin_models.Entidad.objects.get(userid=request.user)
        
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

        return render(request, 'dashboard/entidad/home_entidad.html', {
            'entidad': entidad,
            'cyber_threats_data': mark_safe(json.dumps(cyber_threats_data)),
            'legal_impact_data': mark_safe(json.dumps(legal_impact_data)),
            'detecciones_data': mark_safe(json.dumps(detecciones_data)),
            'accesos_data': mark_safe(json.dumps(accesos_data)),
            'Error':Error,'Success':Success
        })


    def get(self,request:HttpRequest):
        if request.user.is_staff:
            return Index_views.redirigir_usuario(request=request)
        
        entidad = Admin_models.Entidad.objects.get(userid=request.user)
        
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

        return render(request, 'dashboard/entidad/home_entidad.html', {
            'entidad': entidad,
            'cyber_threats_data': mark_safe(json.dumps(cyber_threats_data)),
            'legal_impact_data': mark_safe(json.dumps(legal_impact_data)),
            'detecciones_data': mark_safe(json.dumps(detecciones_data)),
            'accesos_data': mark_safe(json.dumps(accesos_data)),
        })


    
    def post(self,request:HttpRequest):
        return Entidad_Dashboard.Notificacion(request=request)




class Entidades(View):
    @staticmethod
    def Notificacion(request:HttpRequest,Error=None,Success=None):
        if Admin_models.Entidad.objects.filter(userid=request.user):
            return render(request, 'dashboard/entidad/entidades.html',{
                'Error':Error,"Success":Success,'back':request.POST,
                'entidades':Admin_models.Entidad.objects.all(),
            })
        return Index_views.redirigir_usuario(request)

    def get(self, request:HttpRequest):
        if Admin_models.Entidad.objects.filter(userid=request.user):
            return render(request, 'dashboard/entidad/entidades.html',{
                'entidades':Admin_models.Entidad.objects.all(),
            })
        return Index_views.redirigir_usuario(request)

    def post(self, request:HttpRequest):
        if request.user.is_authenticated and request.user.is_staff:
            return Entidades.Notificacion(request)
        return Index_views.redirigir_usuario(request)
    