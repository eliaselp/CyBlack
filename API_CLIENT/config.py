#ENDPOINTS
url_base = "http://localhost:8000/api/"
url_get_public_key_api = url_base + "set_secure_net/"
url_add_url = url_base + "add_url/"
url_query_monitoreo = url_base + "query_monitoreo/"


public_key_hand_check = ""


deteccion_uid = "07a5yrk1b1"
deteccion_api_key = ""
deteccion_secret_key = ""

# Read api_key from api_key.pem
try:
    with open('deteccion/api_key.pem', 'r') as file:
        deteccion_api_key = str(file.read())

    # Read secret_key from secret_key.pem
    with open('deteccion/secret_key.pem', 'r') as file:
        deteccion_secret_key = str(file.read())
except Exception as e:
    deteccion_api_key = ""
    deteccion_secret_key = ""
    deteccion_uid = ""
####################################################


monitoreo_uid = "c8ajimvhdt"
monitoreo_api_key = ""
monitoreo_secret_key = ""

try:
    # Read api_key from api_key.pem
    with open('monitoreo/api_key.pem', 'r') as file:
        monitoreo_api_key = str(file.read())

    # Read secret_key from secret_key.pem
    with open('monitoreo/secret_key.pem', 'r') as file:
        monitoreo_secret_key = str(file.read())
except Exception as e:
    monitoreo_uid = ""
    monitoreo_api_key = ""
    monitoreo_secret_key = ""
