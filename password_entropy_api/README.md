# Password Entropy API

## Descripción
API RESTful para evaluar la fuerza de contraseñas mediante cálculo de entropía. Incluye penalización por contraseñas comunes de un diccionario de 1M passwords.

## Instalación
1. Clona o crea la estructura de carpetas.
2. Instala dependencias: `pip install -r requirements.txt`.
3. Coloca `1millionPasswords.csv` en la raíz.
4. Ejecuta: `python app.py`.

## Uso
- API: POST `/api/v1/password/evaluate` con JSON `{ "password": "tu_contraseña" }`.
- Documentación: http://127.0.0.1:5000/swagger.
- Front-end: Abre `frontend/index.html` (sirve con `python -m http.server 8000` en la raíz).

## Seguridad
- No se almacenan ni loggean contraseñas.
- Evaluación en memoria.

## Ejemplo de Respuesta
```json
{
  "length": 12,
  "keyspace_size": 94,
  "entropy_bits": 78.5,
  "strength": "Fuerte",
  "in_dictionary": false,
  "estimated_crack_time": "1.23e+12 segundos (~39.08 años)",
  "recommendations": ["Incluye símbolos para mayor entropía."]
}