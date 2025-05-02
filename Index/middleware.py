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
            reverse('logout')
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