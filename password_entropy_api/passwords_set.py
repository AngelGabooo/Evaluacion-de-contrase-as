import csv

def load_dictionary(csv_file='1millionPasswords.csv'):
    """Carga contraseñas comunes en un set (solo columna 'password')."""
    common_passwords = set()
    try:
        with open(csv_file, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if 'password' in row and row['password'].strip():
                    common_passwords.add(row['password'].strip().lower())
        print(f'Cargadas {len(common_passwords)} contraseñas únicas.')  # Solo para verificación inicial
    except FileNotFoundError:
        print(f'Archivo {csv_file} no encontrado. Crea el set vacío.')
    return common_passwords