#!/usr/bin/env python3 
from scapy.all import IP, ICMP, Raw, sr1
import sys
import time
import struct
from datetime import datetime

def cifrado_cesar(texto, corrimiento):
    """
    Cifra un texto usando el algoritmo de cifrado César
    
    Args:
        texto (str): El string que será cifrado
        corrimiento (int): La variable de corrimiento
    
    Returns:
        str: El string cifrado
    """
    abecedario = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    abecedario_minuscula = "abcdefghijklmnopqrstuvwxyz"
    
    string_cifrado = ""
    
    for char in texto:
        if char in abecedario:
            posicion_actual = abecedario.index(char)
            nueva_posicion = (posicion_actual + corrimiento) % 26
            string_cifrado += abecedario[nueva_posicion]
        elif char in abecedario_minuscula:
            posicion_actual = abecedario_minuscula.index(char)
            nueva_posicion = (posicion_actual + corrimiento) % 26
            string_cifrado += abecedario_minuscula[nueva_posicion]
        else:
            string_cifrado += char
    
    return string_cifrado

def crear_payload_48_bytes(mensaje, corrimiento, timestamp_actual):
    """
    Crea un payload de exactamente 48 bytes con:
    - Bytes desde 0x10 a 0x37 (40 bytes) conteniendo el mensaje cifrado
    - Timestamp (8 bytes)
    
    Args:
        mensaje (str): Mensaje a cifrar
        corrimiento (int): Corrimiento para cifrado César
        timestamp_actual (float): Timestamp Unix actual
    
    Returns:
        bytes: Payload de exactamente 48 bytes
    """
    # Cifrar el mensaje
    mensaje_cifrado = cifrado_cesar(mensaje, corrimiento)
    mensaje_bytes = mensaje_cifrado.encode('utf-8')
    
    # Crear los 40 bytes base (0x10 a 0x37)
    payload_base = bytearray(range(0x10, 0x38))  # 40 bytes
    
    # Insertar el mensaje cifrado en los primeros bytes disponibles
    # Limitar a máximo 40 bytes para el mensaje
    mensaje_truncado = mensaje_bytes[:40]
    
    # Reemplazar los primeros bytes del payload con el mensaje cifrado
    for i, byte_msg in enumerate(mensaje_truncado):
        if i < 40:
            payload_base[i] = byte_msg
    
    # Si el mensaje es menor a 40 bytes, completar con los valores originales
    # (esto mantiene la secuencia 0x10-0x37 en las posiciones no usadas)
    
    # Agregar timestamp (8 bytes)
    timestamp_bytes = struct.pack('!d', timestamp_actual)
    
    # Payload final de exactamente 48 bytes
    payload_final = bytes(payload_base) + timestamp_bytes
    
    return payload_final, mensaje_cifrado

def enviar_icmp_cifrado(destino, mensaje, corrimiento):
    """
    Envía un paquete ICMP con mensaje cifrado en payload de exactamente 48 bytes
    
    Args:
        destino (str): IP de destino
        mensaje (str): Mensaje a cifrar y enviar
        corrimiento (int): Corrimiento para cifrado César
    """
    # Timestamp actual UTC
    timestamp_actual = time.time()

    # Crear payload de exactamente 48 bytes
    payload_48_bytes, mensaje_cifrado = crear_payload_48_bytes(mensaje, corrimiento, timestamp_actual)
    
    # Verificar que el payload sea exactamente 48 bytes
    assert len(payload_48_bytes) == 48, f"Error: Payload debe ser exactamente 48 bytes, actual: {len(payload_48_bytes)}"
    
    print(f"Mensaje original: '{mensaje}'")
    print(f"Mensaje cifrado (César +{corrimiento}): '{mensaje_cifrado}'")
    print(f"Longitud del mensaje cifrado: {len(mensaje_cifrado)} bytes")
    print(f"Destino: {destino}")
    print()
    
    # Mostrar payload detallado
    print("--- Payload de 48 bytes ---")
    print(f"Total: {len(payload_48_bytes)} bytes")
    print(f"Primeros 40 bytes (con mensaje): {payload_48_bytes[:40].hex()}")
    print(f"Últimos 8 bytes (timestamp): {payload_48_bytes[40:48].hex()}")
    print(f"Payload completo: {payload_48_bytes.hex()}")
    print()
    
    # Mostrar en formato legible
    print("Contenido de los primeros 40 bytes:")
    for i in range(0, 40, 8):
        chunk = payload_48_bytes[i:i+8]
        hex_str = ' '.join([f"{b:02x}" for b in chunk])
        ascii_str = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
        print(f"  {i:02d}-{i+7:02d}: {hex_str:<23} | {ascii_str}")
    
    # Crear paquete ICMP
    ip_layer = IP(dst=destino)
    icmp_layer = ICMP(type=8, code=0)  # Echo Request
    
    # Construir paquete con payload de exactamente 48 bytes
    paquete = ip_layer / icmp_layer / Raw(load=payload_48_bytes)
    
    print("\n--- Información del paquete ---")
    paquete.show()
    
    try:
        print(f"\nEnviando paquete ICMP con mensaje cifrado...")
        respuesta = sr1(paquete, timeout=3, verbose=0)
        
        if respuesta:
            print("✓ Respuesta recibida:")
            print(f"  - Origen: {respuesta.src}")
            print(f"  - Tipo ICMP: {respuesta[ICMP].type}")
            print(f"  - Código ICMP: {respuesta[ICMP].code}")
            
            if respuesta.haslayer(Raw):
                payload_respuesta = respuesta[Raw].load
                print(f"  - Longitud payload respuesta: {len(payload_respuesta)} bytes")
                print(f"  - Payload respuesta: {payload_respuesta.hex()}")
                
                # Intentar descifrar el mensaje de la respuesta
                if len(payload_respuesta) >= 40:
                    try:
                        # Extraer los primeros 40 bytes
                        mensaje_bytes_respuesta = payload_respuesta[:40]
                        
                        # Convertir a string (solo caracteres imprimibles)
                        mensaje_respuesta = ''.join([chr(b) if 32 <= b <= 126 else '' for b in mensaje_bytes_respuesta])
                        
                        # Intentar descifrar
                        mensaje_descifrado = cifrado_cesar(mensaje_respuesta, -corrimiento)
                        print(f"  - Mensaje en respuesta: '{mensaje_respuesta}'")
                        print(f"  - Mensaje descifrado: '{mensaje_descifrado}'")
                        
                    except Exception as e:
                        print(f"  - Error al descifrar respuesta: {e}")
                
                # Extraer timestamp si está presente
                if len(payload_respuesta) >= 48:
                    try:
                        timestamp_respuesta = struct.unpack('!d', payload_respuesta[40:48])[0]
                        timestamp_respuesta_utc = datetime.utcfromtimestamp(timestamp_respuesta)
                        print(f"  - Timestamp respuesta: {timestamp_respuesta_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC")
                        
                        # Calcular RTT
                        rtt = time.time() - timestamp_respuesta
                        print(f"  - RTT: {rtt*1000:.2f} ms")
                    except:
                        print("  - No se pudo extraer timestamp de respuesta")
        else:
            print("✗ No se recibió respuesta (timeout)")
            
    except Exception as e:
        print(f"✗ Error al enviar paquete: {e}")

if __name__ == "__main__":
    # Configuración
    destino_default = "8.8.8.8"
    mensaje_default = "criptografia y seguridad en redes"
    corrimiento_default = 9
    
    # Obtener parámetros
    if len(sys.argv) >= 4:
        destino = sys.argv[1]
        mensaje = sys.argv[2]
        corrimiento = int(sys.argv[3])
    else:
        destino = input(f"IP destino (default: {destino_default}): ").strip() or destino_default
        mensaje = input(f"Mensaje a cifrar (default: {mensaje_default}): ").strip() or mensaje_default
        corrimiento = input(f"Corrimiento César (default: {corrimiento_default}): ").strip()
        corrimiento = int(corrimiento) if corrimiento else corrimiento_default
    
    # Validar IP
    try:
        import ipaddress
        ipaddress.ip_address(destino)
    except ValueError:
        print(f"✗ IP inválida: {destino}")
        sys.exit(1)
    
    # Advertencia sobre longitud del mensaje
    if len(mensaje) > 40:
        print(f"⚠️  Advertencia: El mensaje será truncado a 40 bytes")
        print(f"   Mensaje original: {len(mensaje)} bytes")
        print(f"   Mensaje truncado: {mensaje[:40]}")
        print()
    
    print(f"{'='*60}")
    
    # Enviar paquete
    enviar_icmp_cifrado(destino, mensaje, corrimiento)