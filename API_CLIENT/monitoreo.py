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
import ast
from urllib.parse import urlparse, urlunparse, ParseResult
import config
import ecc
import Base64JsonConvert

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
    os.system('cls' if os.name == 'nt' else 'clear')

def obtener_clave_publica(api_key, uid):
    try:
        private_key, public_key = ecc.generate_keys()
        payload = {
            'public_key_cif': public_key,
            'api_key': api_key,
            'uid': uid
        }

        response = requests.post(
            config.url_get_public_key_api,
            data=payload
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

def parse_tech_data(x):
    if pd.isna(x) or not x.strip():
        return {}
    try:
        return ast.literal_eval(x)
    except (ValueError, SyntaxError):
        try:
            return json.loads(x.replace("'", '"'))
        except json.JSONDecodeError:
            print(f"{Colors.WARNING}Advertencia: Formato no reconocido en datos técnicos: {x}{Colors.ENDC}")
            return {'raw_data': x}

def prepare_request_data_simple(url_only_data, api_key, secret_key, uid):
    data = Base64JsonConvert.Base64JsonConverter.dict_to_base64(data_dict=url_only_data)
    encrypted_data = ecc.encrypt_message(public_key=config.public_key_hand_check, message=data)
    firma = ecc.sign_string(encrypted_data, secret_key)

    return {
        'data': encrypted_data,
        'api_key': api_key,
        'uid': uid,
        'firma': firma
    }

def prepare_request(data, endpoint_url, api_key, secret_key, uid):
    try:
        if not config.public_key_hand_check:
            obtener_clave_publica(api_key=api_key, uid=uid)

        url_only_data = {'url': data.get('url')}
        request_data = prepare_request_data_simple(url_only_data, api_key, secret_key, uid)

        start_time = time.time()
        response = requests.post(
            endpoint_url,
            data=request_data,
            timeout=500
        )
        elapsed_time = time.time() - start_time

        return {
            'response': response.json(),
            'time': elapsed_time,
            'success': True,
            'status_code': response.status_code,
            'url': url_only_data['url']
        }
    except Exception as e:
        return {
            'error': str(e),
            'success': False,
            'status_code': getattr(e, 'status_code', 0),
            'url': data.get('url')
        }

def print_progress(progress, total, current_url, status, errors):
    percent = (progress / total) * 100
    bar_length = 50
    filled_length = int(bar_length * progress // total)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)

    clear_screen()
    print(f"\n{Colors.HEADER}Consultando URLs:{Colors.ENDC}")
    print(f"{Colors.BOLD}[{bar}] {percent:.2f}% ({progress}/{total}){Colors.ENDC}\n")
    print(f"{Colors.OKBLUE}URL actual:{Colors.ENDC} {current_url}")
    print(f"{Colors.OKBLUE}Estado:{Colors.ENDC} {status}")

    if errors:
        print(f"\n{Colors.FAIL}Últimos errores:{Colors.ENDC}")
        for i, error in enumerate(errors[-3:], 1):
            print(f"{i}. {error}")

def show_final_stats(results, total_time):
    success_count = sum(1 for r in results if r.get('success'))
    error_count = len(results) - success_count
    avg_time = total_time / len(results) if results else 0

    error_types = defaultdict(int)
    status_codes = defaultdict(int)
    permitidos = 0
    denegados = 0

    for r in results:
        if r.get('success'):
            message = r['response'].get('message', '').lower()
            if 'denegado' in message:
                denegados += 1
            elif 'permitido' in message:
                permitidos += 1
        else:
            error_types[r.get('error', 'Desconocido')] += 1
        if 'status_code' in r:
            status_codes[r['status_code']] += 1

    clear_screen()
    print(f"\n{Colors.HEADER}{Colors.BOLD}ESTADÍSTICAS FINALES{Colors.ENDC}")
    print("="*50)
    print(f"{Colors.OKGREEN}Total consultado:{Colors.ENDC} {len(results)} URLs")
    print(f"{Colors.OKGREEN}Acceso permitido:{Colors.ENDC} {permitidos}")
    print(f"{Colors.FAIL}Acceso denegado:{Colors.ENDC} {denegados}")
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






def consultar_urls(file_path="./url_evidencias.csv"):
    clear_screen()
    print(f"{Colors.HEADER}Iniciando consultas de acceso a URLs...{Colors.ENDC}")

    try:
        df = pd.read_csv(file_path, dtype=str)
        if 'datos_tecnicos' in df.columns:
            df['datos_tecnicos'] = df['datos_tecnicos'].apply(parse_tech_data)

        records = df.to_dict('records')
        total_urls = len(records)
        results = []
        errors = []
        start_time = time.time()

        with tqdm(total=total_urls, desc="Consultando URLs", unit="URL") as pbar:
            for i, record in enumerate(records, 1):
                current_url = record.get('url', '')
                protocolo = record.get('protocolo','')
                puerto = record.get('puerto','')
                if '' in [current_url,protocolo,puerto]:
                    raise ValueError("URL, protocolo y puerto son requeridos")
                current_url = normalizar_url(url_input=current_url,protocolo=protocolo,puerto=puerto)

                status = f"{Colors.OKGREEN}Consultando...{Colors.ENDC}"

                print_progress(i, total_urls, current_url, status, errors)

                max_attempts = 5
                attempt = 0
                success = False
                result = None
                record['url'] = current_url
                while attempt < max_attempts and not success:
                    result = prepare_request(
                        data=record,
                        endpoint_url=config.url_query_monitoreo,
                        api_key=config.monitoreo_api_key,
                        secret_key=config.monitoreo_secret_key,
                        uid=config.monitoreo_uid
                    )

                    if result.get('status_code') == 405:
                        attempt += 1
                        if attempt < max_attempts:
                            print(f"Intento {attempt} de {max_attempts} - Error 405, reintentando...")
                            time.sleep(1)
                            continue

                    if not result.get('success'):
                        error_msg = f"Error en {current_url} (Código: {result.get('status_code', 'N/A')}): {result.get('error')}"
                        errors.append(error_msg)
                        status = f"{Colors.FAIL}Error{Colors.ENDC}"
                        success = True
                    else:
                        msg = result['response'].get('message', '').lower()
                        if 'denegado' in msg:
                            status = f"{Colors.FAIL}Acceso denegado{Colors.ENDC}"
                        elif 'permitido' in msg:
                            status = f"{Colors.OKGREEN}Acceso permitido{Colors.ENDC}"
                        else:
                            status = f"{Colors.WARNING}Respuesta desconocida{Colors.ENDC}"
                        success = True

                if attempt == max_attempts and result.get('status_code') == 405:
                    error_msg = f"Error persistente en {current_url} (Código: 405 Method Not Allowed después de {max_attempts} intentos)"
                    errors.append(error_msg)
                    status = f"{Colors.FAIL}Error persistente{Colors.ENDC}"

                results.append(result)
                pbar.update(1)
                print_progress(i, total_urls, current_url, status, errors)

        total_time = time.time() - start_time
        show_final_stats(results, total_time)
        return results

    except Exception as e:
        print(f"{Colors.FAIL}Error crítico:{Colors.ENDC} {str(e)}")
        return []

if __name__ == "__main__":
    consultar_urls(file_path="./url_evidencias.csv")
