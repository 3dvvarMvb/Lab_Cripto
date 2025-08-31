def cifrado_cesar(texto, corrimiento):
    # Variable que contiene el abecedario en inglés
    abecedario = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    abecedario_minuscula = "abcdefghijklmnopqrstuvwxyz"
    
    string_cifrado = ""
    
    # Procesar cada carácter del texto
    for char in texto:
        if char in abecedario:
            # Para letras mayúsculas
            posicion_actual = abecedario.index(char)
            nueva_posicion = (posicion_actual + corrimiento) % 26
            string_cifrado += abecedario[nueva_posicion]
        elif char in abecedario_minuscula:
            # Para letras minúsculas
            posicion_actual = abecedario_minuscula.index(char)
            nueva_posicion = (posicion_actual + corrimiento) % 26
            string_cifrado += abecedario_minuscula[nueva_posicion]
        else:
            # Para caracteres que no son letras (espacios, números, signos)
            string_cifrado += char
    
    return string_cifrado

# Ejemplo de uso
if __name__ == "__main__":
    # Parámetros de entrada
    texto_original = input("Ingrese el texto a cifrar: ")
    corrimiento = int(input("Ingrese el corrimiento (número de posiciones a mover): ")) 
    
    # Cifrar el texto
    string_cifrado = cifrado_cesar(texto_original, corrimiento)
    
    print(f"Texto original: {texto_original}")
    print(f"Corrimiento: {corrimiento}")
    print(f"Texto cifrado: {string_cifrado}")