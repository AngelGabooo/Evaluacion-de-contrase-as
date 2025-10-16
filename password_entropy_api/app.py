import math
import re
import os
from flask import Flask, request, jsonify
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS  # Importación para CORS
from passwords_set import load_dictionary

app = Flask(__name__)
CORS(app)  # Habilita CORS para todas las rutas

# Carga global del diccionario (una vez al inicio, no persiste contraseñas evaluadas)
COMMON_PASSWORDS = load_dictionary('1millionPasswords.csv')

def calculate_L(password):
    """Calcula la longitud L de la contraseña."""
    return len(password)

def calculate_N(password):
    """Calcula el tamaño del alfabeto N basado en conjuntos de caracteres usados."""
    n = 0
    if re.search(r'[a-z]', password):
        n += 26  # Lowercase
    if re.search(r'[A-Z]', password):
        n += 26  # Uppercase
    if re.search(r'[0-9]', password):
        n += 10  # Digits
    if re.search(r'[^a-zA-Z0-9]', password):
        n += 32  # Symbols (estimación común)
    return max(n, 1)  # Evitar división por cero

def calculate_entropy(password):
    """Calcula entropía E, penalizando si está en diccionario."""
    L = calculate_L(password)
    N = calculate_N(password)
    E = L * math.log2(N)
    password_lower = password.lower().strip()
    if password_lower in COMMON_PASSWORDS:
        E -= 20  # Penalización por predictibilidad
    return max(E, 0)  # No negativo

def check_password_strength(password, entropy):
    """Evalúa fuerza y tiempo de crackeo."""
    strength = "Débil"
    if entropy >= 80:
        strength = "Muy Fuerte"
    elif entropy >= 60:
        strength = "Fuerte"
    elif entropy > 40:
        strength = "Aceptable"
    
    # Tiempo estimado: 2^E / 10^11 seg (tasa GPU moderna)
    attempts = 2 ** entropy
    rate = 10**11  # intentos/seg
    seconds = attempts / rate
    years = seconds / (365 * 24 * 3600)
    
    in_dict = password.lower().strip() in COMMON_PASSWORDS
    recommendations = []
    if calculate_L(password) < 8:
        recommendations.append("Aumenta la longitud a al menos 8 caracteres.")
    if not re.search(r'[A-Z]', password):
        recommendations.append("Añade al menos una mayúscula.")
    if not re.search(r'[^a-zA-Z0-9]', password):
        recommendations.append("Incluye símbolos para mayor entropía.")
    
    return {
        'strength': strength,
        'in_dictionary': in_dict,
        'estimated_crack_time': f"{seconds:.2e} segundos (~{years:.2e} años)",
        'recommendations': recommendations
    }

@app.route('/api/v1/password/evaluate', methods=['POST'])
def evaluate_password():
    data = request.get_json()
    password = data.get('password', '') if data else ''
    if not password:
        return jsonify({'error': 'Password requerida'}), 400
    
    # NO logging ni storage: Solo evalúa en memoria
    L = calculate_L(password)
    N = calculate_N(password)
    entropy = calculate_entropy(password)
    strength_info = check_password_strength(password, entropy)
    
    return jsonify({
        'length': L,
        'keyspace_size': N,
        'entropy_bits': round(entropy, 2),
        'strength': strength_info['strength'],
        'in_dictionary': strength_info['in_dictionary'],
        'estimated_crack_time': strength_info['estimated_crack_time'],
        'recommendations': strength_info['recommendations']
    })

# Swagger configuración
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Password Entropy API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)