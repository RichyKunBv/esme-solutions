import os
import secrets
import mysql.connector
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta

app = Flask(__name__, static_folder='.', static_url_path='')
app.config['SECRET_KEY'] = os.urandom(24)
CORS(app)

# Almacén de sesiones
sessions = {}
SESSION_TTL = timedelta(minutes=10)

def clean_expired_sessions():
    now = datetime.now()
    expired = [t for t, d in sessions.items() if d['expires'] < now]
    for t in expired:
        del sessions[t]

# ===================== RUTAS PARA ARCHIVOS ESTÁTICOS =====================
# Raíz: sirve login.html desde la subcarpeta ADMON
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/login')
def serve_login():
    return send_from_directory('ADMON', 'login.html')

# Admin.html también desde ADMON
@app.route('/Admin.html')
def serve_admin():
    return send_from_directory('ADMON', 'Admin.html')

# Archivos estáticos desde la raíz (nicepage.css, jquery.js, nicepage.js, etc.)
@app.route('/<path:filename>')
def serve_static(filename):
    # Evitar que capture las rutas de API (ya están definidas antes)
    return send_from_directory('.', filename)

# Imágenes desde la carpeta images/
@app.route('/images/<path:filename>')
def serve_images(filename):
    return send_from_directory('images', filename)

# ===================== ENDPOINTS DE AUTENTICACIÓN =====================
@app.route('/api/validate_credentials', methods=['POST'])
def validate_credentials():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Faltan credenciales'}), 400

    try:
        conn = mysql.connector.connect(
            host='localhost',
            user=username,
            password=password
        )
        cursor = conn.cursor()
        cursor.execute("SHOW DATABASES")
        databases = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        system_dbs = ['information_schema', 'mysql', 'performance_schema', 'sys']
        user_dbs = [db for db in databases if db not in system_dbs]
        return jsonify({'databases': user_dbs}), 200
    except mysql.connector.Error as e:
        return jsonify({'error': f'Credenciales inválidas: {str(e)}'}), 401

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    database = data.get('database')

    if not username or not password or not database:
        return jsonify({'error': 'Faltan datos'}), 400

    try:
        conn = mysql.connector.connect(
            host='localhost',
            user=username,
            password=password,
            database=database
        )
        conn.close()
    except mysql.connector.Error:
        return jsonify({'error': 'No se pudo conectar a la base de datos seleccionada'}), 401

    clean_expired_sessions()
    token = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    sessions[token] = {
        'nonce': nonce,
        'username': username,
        'password': password,
        'database': database,
        'expires': datetime.now() + SESSION_TTL
    }

    return jsonify({'token': token, 'nonce': nonce, 'database': database}), 200

@app.route('/api/validate', methods=['POST'])
def validate():
    data = request.get_json()
    token = data.get('token')
    nonce = data.get('nonce')
    if not token or not nonce:
        return jsonify({'error': 'Token o nonce faltante'}), 400

    clean_expired_sessions()
    session_data = sessions.get(token)
    if not session_data or session_data['nonce'] != nonce:
        if token in sessions:
            del sessions[token]
        return jsonify({'error': 'Sesión inválida (recarga detectada)'}), 401

    session_data['expires'] = datetime.now() + SESSION_TTL
    new_nonce = secrets.token_urlsafe(32)
    session_data['nonce'] = new_nonce

    return jsonify({
        'nonce': new_nonce,
        'username': session_data['username'],
        'database': session_data['database']
    }), 200

# ===================== CRUD PARA COMPUTADORAS =====================
def get_db_connection_from_session(token):
    session_data = sessions.get(token)
    if not session_data:
        return None
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user=session_data['username'],
            password=session_data['password'],
            database=session_data['database']
        )
        return conn
    except mysql.connector.Error:
        return None

@app.route('/api/computadoras', methods=['POST'])
def get_computadoras():
    data = request.get_json()
    token = data.get('token')
    nonce = data.get('nonce')
    if not token or not nonce:
        return jsonify({'error': 'Autenticación requerida'}), 401

    session_data = sessions.get(token)
    if not session_data or session_data['nonce'] != nonce:
        return jsonify({'error': 'Sesión inválida'}), 401

    conn = get_db_connection_from_session(token)
    if not conn:
        return jsonify({'error': 'Error de conexión a BD'}), 500

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM computadoras")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    new_nonce = secrets.token_urlsafe(32)
    session_data['nonce'] = new_nonce
    session_data['expires'] = datetime.now() + SESSION_TTL

    return jsonify({'computadoras': rows, 'nonce': new_nonce}), 200

@app.route('/api/computadoras', methods=['PUT'])
def create_computadora():
    data = request.get_json()
    token = data.get('token')
    nonce = data.get('nonce')
    comp_data = data.get('data')
    if not token or not nonce:
        return jsonify({'error': 'Autenticación requerida'}), 401

    session_data = sessions.get(token)
    if not session_data or session_data['nonce'] != nonce:
        return jsonify({'error': 'Sesión inválida'}), 401

    conn = get_db_connection_from_session(token)
    if not conn:
        return jsonify({'error': 'Error de conexión a BD'}), 500

    cursor = conn.cursor()
    columns = []
    placeholders = []
    values = []
    for key, val in comp_data.items():
        if val is not None:
            columns.append(key)
            placeholders.append('%s')
            values.append(val)
    query = f"INSERT INTO computadoras ({','.join(columns)}) VALUES ({','.join(placeholders)})"
    try:
        cursor.execute(query, values)
        conn.commit()
        new_id = comp_data.get('id')
    except mysql.connector.Error as e:
        return jsonify({'error': str(e)}), 400
    finally:
        cursor.close()
        conn.close()

    new_nonce = secrets.token_urlsafe(32)
    session_data['nonce'] = new_nonce
    session_data['expires'] = datetime.now() + SESSION_TTL

    return jsonify({'message': 'Creada', 'id': new_id, 'nonce': new_nonce}), 201

@app.route('/api/computadoras/<id>', methods=['PUT'])
def update_computadora(id):
    data = request.get_json()
    token = data.get('token')
    nonce = data.get('nonce')
    comp_data = data.get('data')
    if not token or not nonce:
        return jsonify({'error': 'Autenticación requerida'}), 401

    session_data = sessions.get(token)
    if not session_data or session_data['nonce'] != nonce:
        return jsonify({'error': 'Sesión inválida'}), 401

    conn = get_db_connection_from_session(token)
    if not conn:
        return jsonify({'error': 'Error de conexión a BD'}), 500

    cursor = conn.cursor()
    set_clause = []
    values = []
    for key, val in comp_data.items():
        if val is not None:
            set_clause.append(f"{key}=%s")
            values.append(val)
    values.append(id)
    query = f"UPDATE computadoras SET {','.join(set_clause)} WHERE id=%s"
    try:
        cursor.execute(query, values)
        conn.commit()
    except mysql.connector.Error as e:
        return jsonify({'error': str(e)}), 400
    finally:
        cursor.close()
        conn.close()

    new_nonce = secrets.token_urlsafe(32)
    session_data['nonce'] = new_nonce
    session_data['expires'] = datetime.now() + SESSION_TTL

    return jsonify({'message': 'Actualizado', 'nonce': new_nonce}), 200

@app.route('/api/computadoras/<id>', methods=['DELETE'])
def delete_computadora(id):
    data = request.get_json()
    token = data.get('token')
    nonce = data.get('nonce')
    if not token or not nonce:
        return jsonify({'error': 'Autenticación requerida'}), 401

    session_data = sessions.get(token)
    if not session_data or session_data['nonce'] != nonce:
        return jsonify({'error': 'Sesión inválida'}), 401

    conn = get_db_connection_from_session(token)
    if not conn:
        return jsonify({'error': 'Error de conexión a BD'}), 500

    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM computadoras WHERE id=%s", (id,))
        conn.commit()
    except mysql.connector.Error as e:
        return jsonify({'error': str(e)}), 400
    finally:
        cursor.close()
        conn.close()

    new_nonce = secrets.token_urlsafe(32)
    session_data['nonce'] = new_nonce
    session_data['expires'] = datetime.now() + SESSION_TTL

    return jsonify({'message': 'Eliminado', 'nonce': new_nonce}), 200

@app.route('/api/procesadores', methods=['POST'])
def get_procesadores():
    data = request.get_json()
    token = data.get('token')
    nonce = data.get('nonce')
    if not token or not nonce:
        return jsonify({'error': 'Autenticación requerida'}), 401

    session_data = sessions.get(token)
    if not session_data or session_data['nonce'] != nonce:
        return jsonify({'error': 'Sesión inválida'}), 401

    conn = get_db_connection_from_session(token)
    if not conn:
        return jsonify({'error': 'Error de conexión a BD'}), 500

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT nombre FROM procesadores")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    new_nonce = secrets.token_urlsafe(32)
    session_data['nonce'] = new_nonce

    return jsonify({
        'procesadores': [r['nombre'] for r in rows],
        'nonce': new_nonce
    }), 200

# ===================== INICIO =====================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5500, debug=False, threaded=True)