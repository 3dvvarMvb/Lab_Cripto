from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Utilidades
def _to_bytes(data):
    """Convierte una cadena en bytes, interpretando hex si es posible."""
    try:
        cleaned = data.replace(" ", "")
        return bytes.fromhex(cleaned)
    except ValueError:
        return data.encode("utf-8")

def _ensure_length(payload, length):
    payload = payload or b""
    if len(payload) < length:
        payload += get_random_bytes(length - len(payload))
    elif len(payload) > length:
        payload = payload[:length]
    return payload

def _adjust_des_parity(key_bytes):
    if len(key_bytes) % 8 != 0:
        raise ValueError("La clave DES debe tener multiplos de 8 bytes.")

    adjusted = bytearray()
    for byte in key_bytes:
        bits = byte & 0xFE
        # Calcula la paridad impar requerida por DES.
        parity = 1
        for shift in range(7):
            parity ^= (bits >> shift) & 1
        adjusted.append(bits | parity)
    return bytes(adjusted)

def validation_and_adjustment(cipher_config, key_input, iv_input):
    base_key = _to_bytes(key_input)
    key_bytes = _ensure_length(base_key, cipher_config["key_length"])

    if cipher_config.get("requires_parity", False):
        key_bytes = _adjust_des_parity(key_bytes)

    iv_bytes = _ensure_length(_to_bytes(iv_input), cipher_config["iv_length"])

    key_bits = cipher_config["key_length"] * 8
    print(f"Clave final ({key_bits} bits): {key_bytes.hex()}")
    print(f"IV utilizado ({cipher_config['iv_length']} bytes): {iv_bytes.hex()}")

    return key_bytes, iv_bytes


# Encriptacion de los diferentes cifrados
def encrypt_des(plaintext, iv, key):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), DES.block_size))
    return ciphertext

def encrypt_triple_des(plaintext, iv, key):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), DES3.block_size))
    return ciphertext

def encrypt_aes(plaintext, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return ciphertext


# Desencriptacion de los diferentes cifrados
def decrypt_des(ciphertext, iv, key):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted.decode("utf-8")

def decrypt_triple_des(ciphertext, iv, key):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return decrypted.decode("utf-8")

def decrypt_aes(ciphertext, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode("utf-8")


SUPPORTED_CIPHERS = {
    64: {
        "label": "DES",
        "key_length": 8,
        "iv_length": 8,
        "encrypt": encrypt_des,
        "decrypt": decrypt_des,
        "requires_parity": True,
    },
    192: {
        "label": "Triple DES",
        "key_length": 24,
        "iv_length": 8,
        "encrypt": encrypt_triple_des,
        "decrypt": decrypt_triple_des,
        "requires_parity": True,
    },
    256: {
        "label": "AES",
        "key_length": 32,
        "iv_length": 16,
        "encrypt": encrypt_aes,
        "decrypt": decrypt_aes,
    },
}


def demo_cipher(label, encrypt_fn, decrypt_fn, plaintext, key, iv):
    ciphertext = encrypt_fn(plaintext, iv, key)
    print(f"[{label}] Texto plano: {plaintext}")
    print(f"[{label}] Cifrado (hex): {ciphertext.hex()}")
    recovered = decrypt_fn(ciphertext, iv, key)
    print(f"[{label}] Texto recuperado: {recovered}\n")
    return ciphertext, recovered


# Llamada principal
def main():
    try:
        key_size_bits = int(input("Selecciona el tamaño de la clave (64, 192 o 256 bits): "))
    except ValueError:
        print("Selección inválida: debes ingresar un número entero.")
        return

    if key_size_bits not in SUPPORTED_CIPHERS:
        print("Tamaño de clave no válido. Debe ser 64, 192 o 256 bits.")
        return

    raw_key = input("Introduce la clave (texto o hex): ")
    inicialization_vector = input("Introduce el vector de inicialización (IV): ")
    plaintext = input("Introduce el texto plano: ")

    cipher_config = SUPPORTED_CIPHERS[key_size_bits]

    try:
        key, iv = validation_and_adjustment(cipher_config, raw_key, inicialization_vector)
        print("Clave y IV validados correctamente.")

        demo_cipher(
            cipher_config["label"],
            cipher_config["encrypt"],
            cipher_config["decrypt"],
            plaintext,
            key,
            iv,
        )

    except ValueError as e:
        print(f"Error de validación: {e}")

if __name__ == "__main__":  
    main()