from django.shortcuts import redirect
from django.urls import reverse

class AuthAndMFAMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # URLs que no requieren autenticación
        exempt_urls = [
            reverse('login'),
            reverse('mfa'),
            reverse('logout'),
            reverse('set_secure_net'),
            reverse('add_url'),
            reverse('query_monitoreo'),
            reverse('recuperar_clave')
            # Añade aquí otras URLs públicas si es necesario
        ]
        
        # Verificar si la URL actual está exenta
        if request.path in exempt_urls:
            return self.get_response(request)

        # 1. Verificar autenticación
        if not request.user.is_authenticated:
            return redirect('login')

        # 2. Verificar MFA si el usuario tiene secret_mfa
        if (hasattr(request.user, 'secret_mfa') and 
            request.user.secret_mfa is not None and 
            not request.session.get('is_2fa_enabled', False)):
            return redirect('mfa')

        return self.get_response(request)
    




# middleware/logging_middleware.py
import logging
from django.utils import timezone

logger = logging.getLogger('security')
error_logger = logging.getLogger('critical')

class UserActionLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Registrar información básica de la solicitud
        if request.user.is_authenticated:
            user_info = {
                'user': request.user.username,
                'ip': self.get_client_ip(request),
                'action': request.method + ' ' + request.path,
                'extra': {
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'status_code': response.status_code,
                }
            }
            
            logger.info(
                'Acceso de usuario', 
                extra=user_info
            )
            
            # Registrar acciones específicas como POST a URLs críticas
            if request.method == 'POST' and any(
                path in request.path for path in ['/admin/', '/settings/', '/delete/']
            ):
                logger.warning(
                    'Acción crítica realizada', 
                    extra={
                        **user_info,
                        'action': f'CRITICAL ACTION: {request.method} {request.path}',
                        'data': str(getattr(request, request.method, {}))
                    }
                )
        
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip