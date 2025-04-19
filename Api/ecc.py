from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes


#######################################################################################################
def generate_ecdsa_key_pair():
    # Genera la clave privada
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Serializa la clave privada en formato PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Genera la clave pública a partir de la clave privada
    public_key = private_key.public_key()

    # Serializa la clave pública en formato PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem


#####################################################################################################



def sign_string(message: str, private_key_pem: str) -> str:
    # Cargar la clave privada desde el formato PEM
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )

    # Convertir el mensaje a bytes
    message_bytes = message.encode('utf-8')

    # Firmar el mensaje
    signature = private_key.sign(
        message_bytes,
        ec.ECDSA(hashes.SHA256())
    )

    # Codificar la firma en un formato legible (hex)
    r, s = decode_dss_signature(signature)
    signature_hex = f"{r:x}{s:x}"

    return signature_hex

#################################################################################################################

def verify_signature(message: str, signature_hex: str, public_key_pem: str) -> bool:
    # Cargar la clave pública desde el formato PEM
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8')
    )

    # Convertir el mensaje y la firma a bytes
    message_bytes = message.encode('utf-8')
    
    # Decodificar la firma desde el formato hexadecimal
    r = int(signature_hex[:64], 16)
    s = int(signature_hex[64:], 16)
    signature = encode_dss_signature(r, s)

    # Verificar la firma
    try:
        public_key.verify(
            signature,
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        return False



# Ejemplo de uso
#Generar claves
#private_key_pem , public_key_pem = generate_ecdsa_key_pair()

#Firmar texto
#message = "Este es un mensaje de prueba"
#signature = sign_string(message, private_key_pem)

#Validar firma
#signature_hex = "58cbd048e706f9082dbf745d1a0393b64357fc3b276cc2c6c755dec61a1f32d994674a9bc74f5ddb3c1b92c110997798c30d0db3cc76948930b91c395b484e5d"  # Reemplaza con la firma real
#is_valid = verify_signature(message, signature, public_key_pem)
#print("La firma es válida:", is_valid)







import base64
from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key

# Método para generar las claves
def generate_keys():
    eth_key = generate_eth_key()
    private_key = eth_key.to_hex()
    public_key = eth_key.public_key.to_hex()
    return private_key, public_key

# Método para cifrar el mensaje
def encrypt_message(public_key, message):
    encrypted_message = encrypt(public_key, message.encode('utf-8'))
    return base64.b64encode(encrypted_message).decode('utf-8')

# Método para descifrar el mensaje
def decrypt_message(private_key, encrypted_message):
    decoded_message = base64.b64decode(encrypted_message.encode('utf-8'))
    return decrypt(private_key, decoded_message).decode('utf-8')

# Generación de las claves
#private_key, public_key = generate_keys()
#print("Private key:", private_key)
#print("Public key:", public_key)

# Cifrar Mensaje de ejemplo
#message = "Tu mensaje"
#encrypted_message = encrypt_message(public_key, message)
#print("Encrypted message:", encrypted_message)

# Para descifrar el mensaje
#decrypted_message = decrypt_message(private_key, encrypted_message)
#print("Decrypted message:", decrypted_message)