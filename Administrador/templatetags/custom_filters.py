from django import template

register = template.Library()

@register.filter(name='filter_credenciales')
def filter_credenciales(credenciales, entidad_id):
    """Filtra credenciales por ID de entidad"""
    return [c for c in credenciales if c.entidad_id.id == entidad_id]

@register.filter(name='filter_tipo')
def filter_tipo(credenciales, tipo):
    """Filtra credenciales por tipo de sistema"""
    return [c for c in credenciales if c.tipo_sistema == tipo]