
from email.message import EmailMessage
import smtplib



smtp_server = "smtp.gmail.com"
smtp_port = 587
smtp_username = "tradingLiranza@gmail.com"
smtp_password = "gkqnjoscanyjcver"

# Función para enviar correo electrónico
def enviar_correo(email,Asunto,s):
    destinatarios = [email]
    msg = EmailMessage()
    msg['Subject'] = Asunto
    msg['From'] = smtp_username
    msg['To'] = ", ".join(destinatarios)
    msg.set_content(s)
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
    except Exception as e:
        print(f"Error al enviar correo: {e}")




def enviar_correo_con_claves(email, asunto, mensaje, clave_publica_str, clave_privada_str, nombre_archivo_publica="clave_publica.pem", nombre_archivo_privada="clave_privada.pem"):
    """
    Envía un correo con las claves como archivos .pem adjuntos (desde strings).
    
    Args:
        email (str): Correo del destinatario
        asunto (str): Asunto del mensaje
        mensaje (str): Cuerpo del correo
        clave_publica_str (str): Contenido de la clave pública
        clave_privada_str (str): Contenido de la clave privada
        nombre_archivo_publica (str): Nombre para el archivo de clave pública
        nombre_archivo_privada (str): Nombre para el archivo de clave privada
    """
    msg = EmailMessage()
    msg['Subject'] = asunto
    msg['From'] = smtp_username
    msg['To'] = email
    msg.set_content(mensaje)
    
    # Adjuntar clave pública como PEM
    msg.add_attachment(
        clave_publica_str.encode(),  # Convertir string a bytes
        maintype='application',
        subtype='x-pem-file',
        filename=nombre_archivo_publica
    )
    
    # Adjuntar clave privada como PEM
    msg.add_attachment(
        clave_privada_str.encode(),  # Convertir string a bytes
        maintype='application',
        subtype='x-pem-file',
        filename=nombre_archivo_privada
    )
    
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        print("✅ Correo enviado con las claves adjuntas")
    except Exception as e:
        print(f"❌ Error al enviar correo: {e}")
