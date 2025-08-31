#!/usr/bin/env python3
from scapy.all import ICMP, IP, Raw, sniff
import struct
from datetime import datetime

# Diccionario básico de palabras comunes en español
PALABRAS_COMUNES = {
    "el", "la", "los", "las", "un", "una", "unos", "unas", "y", "o", "a", "ante", "bajo", "con", "contra", 
    "de", "desde", "en", "entre", "hacia", "hasta", "para", "por", "según", "sin", "sobre", "tras", 
    "es", "son", "está", "están", "ser", "estar", "haber", "tener", "hacer", "decir", "ir", "ver", "dar", 
    "saber", "querer", "poder", "deber", "poner", "parecer", "quedar", "creer", "hablar", "llevar", "dejar",
    "seguir", "encontrar", "llegar", "volver", "pasar", "estar", "dar", "tomar", "conocer", "pensar",
    "criptografia", "seguridad", "redes", "mensaje", "cifrado", "secreto", "informacion", "datos", "cesar",
    "algoritmo", "corrimiento", "descifrar", "texto", "comunicacion"
}

def descifrado_cesar(texto_cifrado, corrimiento):
    """
    Descifra un texto usando el algoritmo de cifrado César
    
    Args:
        texto_cifrado (str): El texto cifrado
        corrimiento (int): El corrimiento utilizado para descifrar
    
    Returns:
        str: El texto descifrado
    """
    abecedario = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    abecedario_minuscula = "abcdefghijklmnopqrstuvwxyz"
    
    string_descifrado = ""
    
    for char in texto_cifrado:
        if char in abecedario:
            posicion_actual = abecedario.index(char)
            nueva_posicion = (posicion_actual - corrimiento) % 26
            string_descifrado += abecedario[nueva_posicion]
        elif char in abecedario_minuscula:
            posicion_actual = abecedario_minuscula.index(char)
            nueva_posicion = (posicion_actual - corrimiento) % 26
            string_descifrado += abecedario_minuscula[nueva_posicion]
        else:
            string_descifrado += char
    
    return string_descifrado

def analizar_texto(texto):
    """
    Analiza un texto para determinar cuántas palabras conocidas contiene
    
    Args:
        texto (str): El texto a analizar
    
    Returns:
        int: Número de palabras conocidas encontradas
    """
    # Normalizar texto (quitar signos de puntuación y convertir a minúsculas)
    palabras = texto.lower().replace(".", "").replace(",", "").replace("!", "").replace("?", "").split()
    
    # Contar palabras que existen en nuestro diccionario
    contador = 0
    for palabra in palabras:
        if palabra in PALABRAS_COMUNES:
            contador += 1
    
    return contador

def procesar_paquete(paquete):
    """
    Procesa un paquete ICMP para extraer y descifrar el mensaje oculto
    """
    # Verificar si es un paquete ICMP Echo Request (tipo 8)
    if ICMP in paquete and paquete[ICMP].type == 8:
        print("\n¡Capturado paquete ICMP Echo Request!")
        print(f"Origen: {paquete[IP].src}, Destino: {paquete[IP].dst}")
        
        # Verificar si tiene payload
        if Raw in paquete:
            payload = paquete[Raw].load
            print(f"Longitud del payload: {len(payload)} bytes")
            
            # Extraer los primeros 40 bytes (mensaje cifrado)
            if len(payload) >= 40:
                mensaje_cifrado_bytes = payload[:40]
                
                # Convertir a string (solo caracteres imprimibles)
                mensaje_cifrado = ''.join([chr(b) if 32 <= b <= 126 else '' for b in mensaje_cifrado_bytes])
                print(f"Mensaje cifrado extraído: '{mensaje_cifrado}'")
                
                # Intentar descifrar con diferentes corrimientos
                print("\n=== Posibles mensajes descifrados ===")
                
                mejor_corrimiento = 0
                mejor_puntuacion = 0
                mejor_mensaje = ""
                
                for corrimiento in range(1, 26):
                    mensaje_descifrado = descifrado_cesar(mensaje_cifrado, corrimiento)
                    print(f"Corrimiento {corrimiento:2d}: '{mensaje_descifrado}'")
                    
                    # Analizar el texto descifrado
                    puntuacion = analizar_texto(mensaje_descifrado)
                    
                    # Actualizar si encontramos un mejor candidato
                    if puntuacion > mejor_puntuacion:
                        mejor_puntuacion = puntuacion
                        mejor_corrimiento = corrimiento
                        mejor_mensaje = mensaje_descifrado
                
                # Mostrar el resultado del análisis
                if mejor_puntuacion > 0:
                    print("\n=== MENSAJE DETECTADO ===")
                    print(f"Corrimiento detectado: {mejor_corrimiento}")
                    print(f"Mensaje descifrado: '{mejor_mensaje}'")
                    print(f"Palabras reconocidas: {mejor_puntuacion}")
                else:
                    print("\nNo se pudo determinar automáticamente el mensaje original.")
                
                # Extraer timestamp si está presente
                if len(payload) >= 48:
                    try:
                        timestamp = struct.unpack('!d', payload[40:48])[0]
                        timestamp_utc = datetime.utcfromtimestamp(timestamp)
                        print(f"\nTimestamp del mensaje: {timestamp_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC")
                    except:
                        print("\nNo se pudo extraer el timestamp")
            else:
                print("Payload demasiado corto para contener un mensaje cifrado")
        else:
            print("El paquete no contiene payload")
        
        print("="*60)

def iniciar_captura():
    """
    Inicia la captura de paquetes ICMP
    """
    print("="*60)
    print("Iniciando captura de paquetes ICMP...")
    print("Esperando detectar mensajes cifrados con César")
    print("Se analizará automáticamente el mensaje para detectar el corrimiento correcto")
    print("Presiona Ctrl+C para detener la captura")
    print("="*60)
    
    try:
        # Capturar paquetes ICMP
        sniff(filter="icmp", prn=procesar_paquete)
    except KeyboardInterrupt:
        print("\nCaptura de paquetes detenida por el usuario")

if __name__ == "__main__":
    iniciar_captura()