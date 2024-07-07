from flask import Flask, request, jsonify
import sqlite3
import bcrypt

app = Flask(__name__)
DATABASE = 'Gio_Denin_Simon.db'
PORT = 5800

# Inicializar la base de datos y crear la tabla de usuarios
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )''')
        conn.commit()

# Función para añadir un usuario a la base de datos
def add_user(name, password):
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (name, password_hash) VALUES (?, ?)', (name, password_hash))
        conn.commit()

# Función para validar un usuario
def validate_user(name, password):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE name = ?', (name,))
        row = cursor.fetchone()
        if row is None:
            print(f"Usuario {name} no encontrado.")
            return False
        password_hash = row[0]
        if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            print(f"Contraseña para {name} validada correctamente.")
            return True
        else:
            print(f"Contraseña para {name} no coincide.")
            return False

# Endpoint para la raíz
@app.route('/')
def home():
    return 'El servidor Flask está funcionando correctamente.'

# Endpoint para registrar un usuario con /signup/v2
@app.route('/signup/v2', methods=['POST'])
def signup_v2():
    name = request.form.get('username')
    password = request.form.get('password')
    if not name or not password:
        return jsonify({'error': 'Nombre y contraseña son requeridos.'}), 400
    add_user(name, password)
    return jsonify({'message': 'Usuario añadido correctamente.'}), 201

# Endpoint para validar un usuario con /login/v2
@app.route('/login/v2', methods=['POST'])
def login_v2():
    name = request.form.get('username')
    password = request.form.get('password')
    if not name or not password:
        return jsonify({'error': 'Nombre y contraseña son requeridos.'}), 400
    if validate_user(name, password):
        return jsonify({'message': 'Usuario validado correctamente.'}), 200
    else:
        return jsonify({'error': 'Credenciales inválidas.'}), 401

if __name__ == '__main__':
    init_db()
    app.run(port=PORT)
