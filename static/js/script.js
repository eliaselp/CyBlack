document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('loginForm');
    const submitBtn = document.getElementById('submitBtn');
    const buttonText = submitBtn.querySelector('span');
    const originalText = buttonText.textContent;

    // Función para mostrar notificaciones
    function showNotification(message, isSuccess = false) {
        const notification = document.createElement('div');
        notification.className = `notification ${isSuccess ? 'success' : 'error'}`;
        
        // Icono SVG (éxito o error)
        const icon = isSuccess ? `
            <svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
            </svg>
        ` : `
            <svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
            </svg>
        `;
        
        notification.innerHTML = `
            ${icon}
            <span class="message">${message}</span>
            <span class="close-btn">&times;</span>
        `;
        
        document.body.appendChild(notification);
        
        // Animación de entrada
        setTimeout(() => {
            notification.style.opacity = '1';
            notification.style.transform = 'translateY(0)';
        }, 10);
        
        // Auto-eliminar después de 5 segundos
        const autoRemove = setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => notification.remove(), 300);
        }, 5000);
        
        // Cerrar al hacer click
        notification.querySelector('.close-btn').addEventListener('click', () => {
            clearTimeout(autoRemove);
            notification.style.opacity = '0';
            setTimeout(() => notification.remove(), 300);
        });
    }

    // Añadir estilos dinámicamente
    const style = document.createElement('style');
    style.textContent = `
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 16px 24px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
            z-index: 1000;
            opacity: 0;
            transform: translateY(-30px);
            transition: all 0.3s ease-out;
            backdrop-filter: blur(4px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            max-width: 320px;
            color: white;
        }
        
        .error {
            background-color: rgba(239, 68, 68, 0.9);
        }
        
        .success {
            background-color: rgba(34, 197, 94, 0.9);
        }
        
        .icon {
            width: 24px;
            height: 24px;
            flex-shrink: 0;
        }
        
        .message {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            font-size: 14px;
            font-weight: 500;
            line-height: 1.4;
            flex-grow: 1;
        }
        
        .close-btn {
            font-size: 18px;
            cursor: pointer;
            margin-left: 8px;
            opacity: 0.7;
            transition: opacity 0.2s;
        }
        
        .close-btn:hover {
            opacity: 1;
        }
        
        .notification:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 24px rgba(0, 0, 0, 0.2);
        }
    `;
    document.head.appendChild(style);

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Estado de carga
        submitBtn.classList.add('loading');
        buttonText.textContent = 'Autenticando...';
        submitBtn.disabled = true;

        try {
            const formData = new FormData(form);
            const response = await fetch(form.action, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRFToken': form.querySelector('[name=csrfmiddlewaretoken]').value,
                    'Accept': 'application/json'
                }
            });

            const data = await response.json();
            
            if (response.ok) {
                showNotification('¡Autenticación exitosa! Redirigiendo...', true);
                // Pequeño retraso para que se vea la notificación
                setTimeout(() => window.location.reload(), 1500);
            } else {
                showNotification(data.message || 'Error de autenticación');
            }
        } catch (error) {
            showNotification('Error de conexión con el servidor');
            console.error('Error:', error);
        } finally {
            submitBtn.classList.remove('loading');
            buttonText.textContent = originalText;
            submitBtn.disabled = false;
        }
    });
});