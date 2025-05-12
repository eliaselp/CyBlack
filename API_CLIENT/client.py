import requests
import json
import os
import base64
import random
import pandas as pd
import time
from datetime import datetime
import sys
from tqdm import tqdm
from collections import defaultdict
import ast  # Nuevo import para el parsing seguro

import config
import ecc
import Base64JsonConvert

# Configuración de colores para la consola
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def clear_screen():
    """Limpia la pantalla de la consola"""
    os.system('cls' if os.name == 'nt' else 'clear')

def obtener_clave_publica() -> str:
    """Obtiene la clave pública desde el endpoint API"""
    try:
        private_key, public_key = ecc.generate_keys()
        payload = {
            'public_key_cif': public_key,
            'api_key': config.api_key,
            'uid': config.uid
        }
        
        response = requests.post(
            config.url_get_public_key_api,
            data=payload,
            headers={}
        )
        response.raise_for_status()
        data = response.json()
        
        if data.get('status') != 'success' or 'public_key' not in data:
            raise ValueError("La respuesta no tiene el formato esperado")
            
        public_key = ecc.decrypt_message(private_key=private_key, encrypted_message=data['public_key'])
        config.public_key_hand_check = public_key
        return True
    except Exception as e:
        raise Exception(f"Error al obtener clave pública: {str(e)}")

def get_random_file():
    """Obtiene un archivo aleatorio de evidencias"""
    if not os.path.exists(RESOURCES_DIR):
        os.makedirs(RESOURCES_DIR)
        raise Exception(f"Directorio {RESOURCES_DIR} no existe")
    
    files = [f for f in os.listdir(RESOURCES_DIR) if os.path.isfile(os.path.join(RESOURCES_DIR, f))]
    if not files:
        raise Exception(f"No hay archivos en {RESOURCES_DIR}")
    
    return os.path.join(RESOURCES_DIR, random.choice(files))

def parse_tech_data(x):
    """Parsea de forma segura los datos técnicos"""
    if pd.isna(x) or not x.strip():
        return {}
    try:
        # Primero intentamos con ast.literal_eval para manejar diccionarios Python
        return ast.literal_eval(x)
    except (ValueError, SyntaxError):
        try:
            # Si falla, intentamos con json.loads (para JSON válido)
            return json.loads(x.replace("'", '"'))
        except json.JSONDecodeError:
            print(f"{Colors.WARNING}Advertencia: Formato no reconocido en datos técnicos: {x}{Colors.ENDC}")
            return {'raw_data': x}

def prepare_request_data(data):
    """Prepara los datos para la solicitud POST"""
    data = Base64JsonConvert.Base64JsonConverter.dict_to_base64(data_dict=data)
    encrypted_data = ecc.encrypt_message(public_key=config.public_key_hand_check, message=data) 
    firma = ecc.sign_string(encrypted_data, config.secret_key)
    file_path = get_random_file()
    
    return {
        'data': encrypted_data,
        'api_key': config.api_key,
        'uid': config.uid,
        'firma': firma,
        'file': open(file_path, 'rb')
    }

def prepare_request(data, endpoint_url):
    """Envía una solicitud a la API"""
    try:
        if not config.public_key_hand_check:
            obtener_clave_publica()
            
        request_data = prepare_request_data(data=data)
        files = {'archivo_evidencia': request_data.get('file')}
        
        start_time = time.time()
        response = requests.post(
            endpoint_url,
            data={
                'data': request_data['data'],
                'api_key': request_data['api_key'],
                'uid': request_data['uid'],
                'firma': request_data['firma']
            },
            files=files,
            timeout=30  # Añadido timeout para evitar esperas infinitas
        )
        elapsed_time = time.time() - start_time
        
        if request_data.get('file'):
            request_data['file'].close()
        
        return {
            'response': response.json(),
            'time': elapsed_time,
            'success': True,
            'status_code': response.status_code
        }
    except Exception as e:
        return {
            'error': str(e),
            'success': False,
            'status_code': getattr(e, 'status_code', 0)
        }

def print_progress(progress, total, current_url, status, errors):
    """Muestra el progreso actual en la consola"""
    percent = (progress / total) * 100
    bar_length = 50
    filled_length = int(bar_length * progress // total)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    
    clear_screen()
    print(f"\n{Colors.HEADER}Procesando URLs:{Colors.ENDC}")
    print(f"{Colors.BOLD}[{bar}] {percent:.2f}% ({progress}/{total}){Colors.ENDC}\n")
    
    print(f"{Colors.OKBLUE}URL actual:{Colors.ENDC} {current_url}")
    print(f"{Colors.OKBLUE}Estado:{Colors.ENDC} {status}")
    
    if errors:
        print(f"\n{Colors.FAIL}Últimos errores:{Colors.ENDC}")
        for i, error in enumerate(errors[-3:], 1):
            print(f"{i}. {error}")

def show_final_stats(results, total_time):
    """Muestra las estadísticas finales del proceso"""
    success_count = sum(1 for r in results if r.get('success'))
    error_count = len(results) - success_count
    avg_time = total_time / len(results) if results else 0
    
    error_types = defaultdict(int)
    status_codes = defaultdict(int)
    
    for r in results:
        if not r.get('success'):
            error_types[r.get('error', 'Desconocido')] += 1
        if 'status_code' in r:
            status_codes[r['status_code']] += 1
    
    clear_screen()
    print(f"\n{Colors.HEADER}{Colors.BOLD}ESTADÍSTICAS FINALES{Colors.ENDC}")
    print("="*50)
    print(f"{Colors.OKGREEN}Total procesado:{Colors.ENDC} {len(results)} URLs")
    print(f"{Colors.OKGREEN}Éxitos:{Colors.ENDC} {success_count}")
    print(f"{Colors.FAIL}Errores:{Colors.ENDC} {error_count}")
    print(f"{Colors.OKBLUE}Tiempo total:{Colors.ENDC} {total_time:.2f} segundos")
    print(f"{Colors.OKBLUE}Tiempo promedio por URL:{Colors.ENDC} {avg_time:.2f} segundos")
    
    if status_codes:
        print(f"\n{Colors.OKBLUE}Códigos de estado HTTP:{Colors.ENDC}")
        for code, count in status_codes.items():
            print(f"- {code}: {count} ocurrencias")
    
    if error_types:
        print(f"\n{Colors.WARNING}{Colors.BOLD}Tipos de errores:{Colors.ENDC}")
        for error, count in error_types.items():
            print(f"- {error}: {count} ocurrencias")

def add_url(file_path="./url_evidencias.csv"):
    """Procesa un archivo CSV con URLs y envía los datos a la API"""
    clear_screen()
    print(f"{Colors.HEADER}Iniciando procesamiento de URLs...{Colors.ENDC}")
    
    try:
        # Leer el archivo CSV
        df = pd.read_csv(file_path, dtype=str)
        
        # Procesar datos_tecnicos
        if 'datos_tecnicos' in df.columns:
            df['datos_tecnicos'] = df['datos_tecnicos'].apply(parse_tech_data)
        
        records = df.to_dict('records')
        total_urls = len(records)
        results = []
        errors = []
        start_time = time.time()
        
        # Barra de progreso con tqdm
        with tqdm(total=total_urls, desc="Procesando URLs", unit="URL") as pbar:
            for i, record in enumerate(records, 1):
                current_url = record.get('url', 'Sin URL')
                status = f"{Colors.OKGREEN}Procesando...{Colors.ENDC}"
                
                print_progress(i, total_urls, current_url, status, errors)
                
                result = prepare_request(data=record, endpoint_url=config.url_add_url)
                
                if not result.get('success'):
                    error_msg = f"Error en {current_url} (Código: {result.get('status_code', 'N/A')}: {result.get('error')}"
                    errors.append(error_msg)
                    status = f"{Colors.FAIL}Error{Colors.ENDC}"
                else:
                    status = f"{Colors.OKGREEN}Éxito (Código: {result.get('status_code', 'N/A')}{Colors.ENDC}"
                
                results.append(result)
                pbar.update(1)
                print_progress(i, total_urls, current_url, status, errors)
        
        total_time = time.time() - start_time
        show_final_stats(results, total_time)
        return results
        
    except Exception as e:
        print(f"{Colors.FAIL}Error crítico:{Colors.ENDC} {str(e)}")
        return []

# Configuración inicial
RESOURCES_DIR = os.path.join(os.path.dirname(__file__), "recursos/evidencias")

if __name__ == "__main__":
    add_url(file_path="./url_evidencias.csv")