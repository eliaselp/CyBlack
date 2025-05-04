import base64
import json
from django.core.exceptions import ValidationError

class Base64JsonConverter:
    
    @staticmethod
    def base64_to_dict(base64_str: str) -> dict:
        """
        Convierte un string Base64 a un diccionario Python
        
        Args:
            base64_str (str): String codificado en Base64 que representa un JSON
            
        Returns:
            dict: Diccionario con los datos decodificados
            
        Raises:
            ValidationError: Si el Base64 o JSON no son válidos
        """
        try:
            # Decodificar Base64
            decoded_bytes = base64.b64decode(base64_str)
            decoded_str = decoded_bytes.decode('utf-8')
            
            # Convertir JSON a diccionario
            data_dict = json.loads(decoded_str)
            
            if not isinstance(data_dict, dict):
                raise ValidationError("El JSON decodificado no es un objeto/diccionario válido")
                
            return data_dict
            
        except base64.binascii.Error as e:
            raise ValidationError(f"Error al decodificar Base64: {str(e)}")
        except json.JSONDecodeError as e:
            raise ValidationError(f"Error al decodificar JSON: {str(e)}")
        except UnicodeDecodeError as e:
            raise ValidationError(f"Error al decodificar texto UTF-8: {str(e)}")
    
    @staticmethod
    def dict_to_base64(data_dict: dict) -> str:
        """
        Convierte un diccionario Python a un string Base64
        
        Args:
            data_dict (dict): Diccionario a codificar
            
        Returns:
            str: String en Base64 que representa el JSON del diccionario
            
        Raises:
            ValidationError: Si el diccionario no es serializable a JSON
        """
        try:
            # Validar que sea un diccionario
            if not isinstance(data_dict, dict):
                raise ValidationError("El dato de entrada debe ser un diccionario")
            
            # Convertir a JSON
            json_str = json.dumps(data_dict, ensure_ascii=False)
            
            # Codificar a Base64
            base64_bytes = base64.b64encode(json_str.encode('utf-8'))
            return base64_bytes.decode('utf-8')
            
        except (TypeError, ValueError) as e:
            raise ValidationError(f"Error al serializar a JSON: {str(e)}")