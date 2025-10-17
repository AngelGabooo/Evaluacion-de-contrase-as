import math
import re
import os
import difflib  # NUEVO: Para similitudes de strings (built-in)
from flask import Flask, request, jsonify
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
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
        E -= 20  
    return max(E, 0)  

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
    
    # MODIFICADO: Detección de subcadenas o similitudes, con case y parcial/exacta
    password_lower = password.lower().strip()
    password_original = password.strip()  # NUEVO: Guarda original para case
    similar_matches = []
    in_dict = False
    is_partial = False  # NUEVO: Flag para parcial vs. exacta completa
    
    # Función auxiliar para obtener posiciones de case
    def get_case_positions(word_orig):
        upper_pos = [i+1 for i, char in enumerate(word_orig) if char.isupper()]  # Posiciones mayús (1-indexed)
        lower_pos = [i+1 for i, char in enumerate(word_orig) if char.islower()]  # Posiciones minús
        if upper_pos and lower_pos:
            return f"mayúsculas en posiciones {upper_pos}; minúsculas en {lower_pos}"
        elif upper_pos:
            return f"mayúsculas en posiciones {upper_pos}"
        elif lower_pos:
            return f"minúsculas en posiciones {lower_pos}"
        else:
            return "sin letras (solo números/símbolos)"
    
    # Chequea coincidencia exacta completa (no parcial)
    if password_lower in COMMON_PASSWORDS:
        in_dict = True
        # MODIFICADO: Detecta case del input original con posiciones
        case_details = get_case_positions(password_original)
        similar_matches.append(f"Coincidencia exacta (no parcial) con '{password_lower}' ({case_details})")
    else:
        is_partial = True  
        words_lower = re.split(r'[\.\s\-_]+', password_lower)  
        words_original = re.split(r'[\.\s\-_]+', password_original)  
        for i, word_lower in enumerate(words_lower):
            word_orig = words_original[i]  
            if len(word_lower) > 2:  
                # Chequea coincidencia exacta en subcadenas (parcial)
                if word_lower in COMMON_PASSWORDS:
                    case_details = get_case_positions(word_orig)
                    similar_matches.append(f"Coincidencia parcial con subcadena '{word_lower}' ({case_details})")
                # Chequea similitudes  en subcadenas (parcial)
                matches = difflib.get_close_matches(word_lower, COMMON_PASSWORDS, n=3, cutoff=0.8)
                for match in matches:
                    ratio = difflib.SequenceMatcher(None, word_lower, match).ratio()
                    case_details = get_case_positions(word_orig)
                    similar_matches.append(f"Similitud parcial con subcadena '{word_lower}' a '{match}' (similitud {ratio:.2f}, {case_details})")
    
    # Si hay matches, penaliza 
    recommendations = []
    if calculate_L(password) < 8:
        recommendations.append("Aumenta la longitud a al menos 8 caracteres.")
    if not re.search(r'[A-Z]', password):
        recommendations.append("Añade al menos una mayúscula.")
    if not re.search(r'[^a-zA-Z0-9]', password):
        recommendations.append("Incluye símbolos para mayor entropía.")
    if similar_matches:
        type_match = "parcial" if is_partial else "exacta completa"
        recommendations.append(f"Evita coincidencias {type_match}; usa variaciones únicas.")
    
    return {
        'strength': strength,
        'in_dictionary': in_dict,
        'similar_matches': similar_matches,  
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
        'similar_matches': strength_info['similar_matches'],  # NUEVO: Incluido en respuesta
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