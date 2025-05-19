import random

def generar_codigo_verificacion():
    codigo = ''.join(random.choices('0123456789', k=10))
    return codigo



import re
def validar_contraseñas(pass1: str, pass2: str) -> str:
    errores = []
    if pass1 != pass2:
        return "Las contraseñas no coinciden"
    if len(pass1) < 8:
        errores.append("Debe tener al menos 8 caracteres")
    if not re.search(r"[A-Z]", pass1):
        errores.append("Debe contener al menos una letra mayúscula")
    if not re.search(r"[a-z]", pass1):
        errores.append("Debe contener al menos una letra minúscula")
    if not re.search(r"\d", pass1):
        errores.append("Debe contener al menos un número")
    if not re.search(r"[^\w\s]", pass1):
        errores.append("Debe contener al menos un carácter especial")
    return "OK" if not errores else ", ".join(errores)
