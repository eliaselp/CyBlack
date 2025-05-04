import requests
import json
import os
import base64
import random
from datetime import datetime, timedelta
from . import config, ecc, Base64JsonConvert


def obtener_clave_publica() -> str:
    """
    Obtiene la clave pública desde un endpoint API con autenticación
    
    Args:
        url_api (str): URL del endpoint
        public_key_cif (str): Clave pública cifrada
        api_key (str): API key para autenticación
        uid (str): Identificador único de usuario
        
    Returns:
        str: Clave pública en formato PEM
        
    Raises:
        Exception: Si hay errores en la conexión o formato de respuesta
    """
    try:
        #Preparar claves de hand_check
        private_key, public_key = ecc.generate_keys()
        # Datos para el POST
        payload = {
            'public_key_cif': public_key,
            'api_key': config.api_key,
            'uid': config.uid
        }
        
        
        # Hacer la petición POST
        response = requests.post(
            config.url_get_public_key_api,
            data=payload,
            headers={}
        )
        
        # Verificar que la respuesta sea exitosa
        response.raise_for_status()
        
        # Parsear la respuesta JSON
        data = response.json()
        
        # Verificar la estructura esperada
        if data.get('status') != 'success' or 'public_key' not in data:
            raise ValueError("La respuesta no tiene el formato esperado")
            
        public_key = ecc.decrypt_message(private_key=private_key,encrypted_message=data['public_key'])
        config.public_key_hand_check = public_key
        print('Handcheck realizado correctamente')
        return
    except requests.exceptions.RequestException as e:
        raise Exception(f"Error de conexión: {str(e)}")
    except json.JSONDecodeError:
        raise Exception("La respuesta no es un JSON válido")
    except Exception as e:
        raise Exception(f"Error al obtener clave pública: {str(e)}")





















# Configuración inicial
API_URL = "http://tu-api.com/add_url"  # Cambiar por la URL real de tu API
RESOURCES_DIR = os.path.join(os.path.dirname(__file__), "recursos/evidencias")

def get_random_file():
    """Obtiene un archivo aleatorio de la carpeta de evidencias"""
    if not os.path.exists(RESOURCES_DIR):
        os.makedirs(RESOURCES_DIR)
        raise Exception(f"Directorio {RESOURCES_DIR} no existe. Crea la carpeta y añade archivos de evidencia.")
    
    files = [f for f in os.listdir(RESOURCES_DIR) if os.path.isfile(os.path.join(RESOURCES_DIR, f))]
    if not files:
        raise Exception(f"No hay archivos en {RESOURCES_DIR}")
    
    return os.path.join(RESOURCES_DIR, random.choice(files))

def generate_mock_data():
    """Genera datos aleatorios creíbles basados en los modelos"""
    # Datos para URL_Maliciosa
    protocolo = random.choice(['HTTP', 'HTTPS', 'FTP'])
    puerto = random.choice([80, 443, 21, 22, 8080])
    dominio = random.choice(['phishing', 'malware', 'scam']) + random.choice(['.com', '.net', '.org'])
    path = '/' + '/'.join([random.choice(['login', 'download', 'secure', 'update']) for _ in range(2)])
    
    url_data = {
        'protocolo': protocolo,
        'puerto': puerto,
        'url': f"{protocolo.lower()}://{dominio}{path}",
        'ip': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
        'objetivo': random.choice(['ILICITO', 'ECONOMIA', 'INFRAESTRUCTURA']),
        'metodo': random.choice(['ENGANIO', 'TECNICO', 'EVASION']),
        'impacto_legal': random.choice(['GRAVE', 'MODERADO', 'LEVE']),
        'descripcion_url': f"Sitio de {random.choice(['phishing', 'malware', 'scam'])} que imita a {random.choice(['banco', 'red social', 'servicio público'])}",
    }
    
    # Datos para Evidencia
    evidencia_data = {
        'metodo_deteccion': random.choice(['FIRMA', 'HEURISTICA', 'MACHINE_LEARNING', 'REPUTACION']),
        'descripcion_evidencia': f"Detección mediante {random.choice(['análisis de tráfico', 'scaneo automático', 'reporte de usuario'])}",
        'datos_tecnicos': json.dumps({
            'headers': {
                'Server': random.choice(['Apache', 'Nginx', 'IIS']),
                'X-Powered-By': random.choice(['PHP', 'ASP.NET', 'Node.js'])
            },
            'ssl': random.choice([True, False]),
            'technologies': [
                random.choice(['jQuery', 'React', 'Vue.js']),
                random.choice(['PHP', 'Node.js', 'Python'])
            ]
        })
    }
    
    return {**url_data, **evidencia_data}



def prepare_request_data():
    """Prepara todos los datos para la solicitud POST"""
    # 1. Generar datos aleatorios
    data = generate_mock_data()
    
    # 2. Convertir a JSON y cifrar con ECIES
    data = Base64JsonConvert.Base64JsonConverter.dict_to_base64(data_dict=data)
    encrypted_data = ecc.encrypt_message(public_key=config.public_key_hand_check, message=data) 
    
    # 3. Firmar el mensaje cifrado
    firma = ecc.sign_string(encrypted_data, config.secret_key)
    
    # 4. Obtener archivo de evidencia
    file_path = get_random_file()
    
    return {
        'data': encrypted_data,
        'api_key': config.api_key,
        'uid': config.uid,
        'firma': firma,
        'file': open(file_path, 'rb')
    }




def send_request():
    """Envía la solicitud POST a la API"""
    try:
        # Preparar datos
        obtener_clave_publica()
        request_data = prepare_request_data()
        files = {'archivo_evidencia': request_data['file']}
        
        # Enviar solicitud
        response = requests.post(
            API_URL,
            data={
                'data': request_data['data'],
                'api_key': request_data['api_key'],
                'uid': request_data['uid'],
                'firma': request_data['firma']
            },
            files=files
        )
        
        # Cerrar el archivo
        request_data['file'].close()
        
        return response.json()
    except Exception as e:
        return {'error': str(e)}


