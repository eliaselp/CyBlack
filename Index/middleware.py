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





# middleware/audit_middleware.py
import structlog
from django.utils.deprecation import MiddlewareMixin

logger = structlog.get_logger("audit")

class AuditContextMiddleware(MiddlewareMixin):
    def process_request(self, request):
        structlog.contextvars.bind_contextvars(
            user_id=getattr(request.user, 'id', None),
            user_ip=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT'),
            request_path=request.path,
        )










# Index/middleware.py
from request_logging.middleware import LoggingMiddleware
import json
import logging

class FixedLoggingMiddleware(LoggingMiddleware):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Configuramos un logger estándar
        self.std_logger = logging.getLogger('django.request')
        
    def _get_content(self, response):
        """Obtiene el contenido de forma segura"""
        try:
            if hasattr(response, 'content'):
                content = response.content
                if isinstance(content, bytes):
                    return content.decode('utf-8', errors='replace')
                return content
            return None
        except Exception as e:
            self.std_logger.warning(f"Error getting content: {str(e)}")
            return None

    def _log_resp(self, level, response, logging_context):
        """Versión completamente compatible"""
        try:
            # Preparamos el mensaje de log
            log_msg = {
                'status': response.status_code,
                'headers': dict(response.items()) if hasattr(response, 'items') else {},
                'content': self._get_content(response),
                **logging_context
            }
            
            # Formateamos como string para evitar problemas con el logger
            log_str = "\n".join([f"{k}: {v}" for k, v in log_msg.items()])
            
            # Usamos el logger estándar que sí soporta estos parámetros
            self.std_logger.log(level, log_str)
            
        except Exception as e:
            self.std_logger.error(f"Logging error: {str(e)}", exc_info=True)