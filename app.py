from flask import Flask, render_template, request, jsonify
import base64
import hashlib
import bcrypt
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import json

app = Flask(__name__)

class Processor:
    @staticmethod
    def base64_encode(text):
        try:
            return base64.b64encode(text.encode()).decode()
        except Exception as e:
            return f"Error en Base64 encode: {str(e)}"

    @staticmethod
    def base64_decode(text):
        try:
            return base64.b64decode(text).decode()
        except Exception as e:
            return f"Error en Base64 decode: {str(e)}"

    @staticmethod
    def aes_encrypt(text, key):
        try:
            key = hashlib.sha256(key.encode()).digest()
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
            return base64.b64encode(iv + ct_bytes).decode('utf-8')
        except Exception as e:
            return f"Error en AES encrypt: {str(e)}"

    @staticmethod
    def aes_decrypt(text, key):
        try:
            key = hashlib.sha256(key.encode()).digest()
            encrypted = base64.b64decode(text)
            iv = encrypted[:16]
            ct = encrypted[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode('utf-8')
        except Exception as e:
            return f"Error en AES decrypt: {str(e)}"

    @staticmethod
    def des_encrypt(text, key):
        try:
            # Asegurar que la clave tenga el tamaño correcto para 3DES
            key_hash = hashlib.sha256(key.encode()).digest()[:24]
            # Generar IV aleatorio
            iv = get_random_bytes(8)  # DES usa bloques de 8 bytes
            # Crear cipher
            cipher = DES3.new(key_hash, DES3.MODE_CBC, iv)
            # Encriptar
            padded_text = pad(text.encode(), DES3.block_size)
            encrypted = cipher.encrypt(padded_text)
            # Combinar IV y texto cifrado y convertir a base64
            result = base64.b64encode(iv + encrypted).decode('utf-8')
            return result
        except Exception as e:
            return f"Error en 3DES encrypt: {str(e)}"

    @staticmethod
    def des_decrypt(text, key):
        try:
            # Preparar la clave
            key_hash = hashlib.sha256(key.encode()).digest()[:24]
            # Decodificar el texto de base64
            encrypted = base64.b64decode(text)
            # Separar IV y texto cifrado
            iv = encrypted[:8]  # DES usa bloques de 8 bytes
            ct = encrypted[8:]
            # Crear cipher
            cipher = DES3.new(key_hash, DES3.MODE_CBC, iv)
            # Descifrar
            padded_text = cipher.decrypt(ct)
            result = unpad(padded_text, DES3.block_size).decode('utf-8')
            return result
        except Exception as e:
            return f"Error en 3DES decrypt: {str(e)}"

    @staticmethod
    def md5(text):
        try:
            return hashlib.md5(text.encode()).hexdigest()
        except Exception as e:
            return f"Error en MD5: {str(e)}"

    @staticmethod
    def sha256(text):
        try:
            return hashlib.sha256(text.encode()).hexdigest()
        except Exception as e:
            return f"Error en SHA256: {str(e)}"

    @staticmethod
    def sha512(text):
        try:
            return hashlib.sha512(text.encode()).hexdigest()
        except Exception as e:
            return f"Error en SHA512: {str(e)}"

    @staticmethod
    def bcrypt(text):
        try:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(text.encode(), salt)
            return hashed.decode()
        except Exception as e:
            return f"Error en bcrypt: {str(e)}"

    @staticmethod
    def vigenere_encrypt(text, key):
        try:
            if not key:
                raise ValueError("La clave no puede estar vacía")
            
            # Función para procesar solo letras
            def is_letter(char):
                return char.isalpha()

            # Convertir todo a mayúsculas para simplificar
            text = text.upper()
            key = key.upper()
            
            # Generar la clave repetida para que coincida con la longitud del texto
            key_repeated = ''
            key_index = 0
            for char in text:
                if is_letter(char):
                    key_repeated += key[key_index % len(key)]
                    key_index += 1
                else:
                    key_repeated += char

            # Cifrar el texto
            result = ''
            for i in range(len(text)):
                if is_letter(text[i]):
                    # Convertir letras a números (A=0, B=1, etc.)
                    text_num = ord(text[i]) - ord('A')
                    key_num = ord(key_repeated[i]) - ord('A')
                    # Aplicar el cifrado Vigenère
                    encrypted_num = (text_num + key_num) % 26
                    # Convertir de nuevo a letra
                    result += chr(encrypted_num + ord('A'))
                else:
                    # Mantener caracteres no alfabéticos sin cambios
                    result += text[i]
            
            return result
        except Exception as e:
            return f"Error en Vigenère encrypt: {str(e)}"

    @staticmethod
    def vigenere_decrypt(text, key):
        try:
            if not key:
                raise ValueError("La clave no puede estar vacía")
            
            # Función para procesar solo letras
            def is_letter(char):
                return char.isalpha()

            # Convertir todo a mayúsculas para simplificar
            text = text.upper()
            key = key.upper()
            
            # Generar la clave repetida
            key_repeated = ''
            key_index = 0
            for char in text:
                if is_letter(char):
                    key_repeated += key[key_index % len(key)]
                    key_index += 1
                else:
                    key_repeated += char

            # Descifrar el texto
            result = ''
            for i in range(len(text)):
                if is_letter(text[i]):
                    # Convertir letras a números (A=0, B=1, etc.)
                    text_num = ord(text[i]) - ord('A')
                    key_num = ord(key_repeated[i]) - ord('A')
                    # Aplicar el descifrado Vigenère
                    decrypted_num = (text_num - key_num) % 26
                    # Convertir de nuevo a letra
                    result += chr(decrypted_num + ord('A'))
                else:
                    # Mantener caracteres no alfabéticos sin cambios
                    result += text[i]
            
            return result
        except Exception as e:
            return f"Error en Vigenère decrypt: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No se recibieron datos'}), 400

        input_text = data.get('input', '')
        operations = data.get('operations', [])

        if not operations:
            return jsonify({'error': 'No hay operaciones para procesar'}), 400

        processor = Processor()
        result = input_text

        for operation in operations:
            op_type = operation.get('type', '')
            
            if not hasattr(processor, op_type):
                return jsonify({'error': f'Operación no soportada: {op_type}'}), 400

            method = getattr(processor, op_type)
            
            # Verificar si la operación necesita una clave
            if op_type in ['aes_encrypt', 'aes_decrypt', 'des_encrypt', 'des_decrypt', 
                          'vigenere_encrypt', 'vigenere_decrypt']:
                key = operation.get('key', '')
                if not key:
                    return jsonify({'error': 'Se requiere una clave para el cifrado'}), 400
                result = method(result, key)
            else:
                result = method(result)

        return jsonify({'output': result})

    except Exception as e:
        app.logger.error(f"Error en process: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=4444)