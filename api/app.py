from flask import Flask, jsonify, request
from functools import wraps
import psycopg2, os, bcrypt, jwt
from datetime import datetime, timedelta

app = Flask(__name__)

# Secret key for JWT signing
SECRET_KEY = os.getenv('SECRET_KEY', 'fallback-secret-key')

# ---- DATABASE CONNECTION ----
def get_db():
    return psycopg2.connect(os.getenv('DATABASE_URL'))

# ---- CREATE TABLES ON STARTUP ----
def setup():
    conn = get_db()
    cur = conn.cursor()

    # Users table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    ''')

    # Todos table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS todos (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            title TEXT NOT NULL,
            completed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    ''')

    conn.commit()
    cur.close()
    conn.close()

setup()

# ---- JWT HELPER FUNCTIONS ----

# Generate a token for a user
def generate_token(user_id, email):
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Decode and verify a token
def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# ---- AUTH DECORATOR ----
# This protects routes that require login
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get token from request header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No token provided'}), 401
        token = auth_header.split(' ')[1]
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        # Attach user info to request
        request.user_id = payload['user_id']
        request.email   = payload['email']
        return f(*args, **kwargs)
    return decorated

# ---- HEALTH CHECK ----
@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'time': str(datetime.now())
    })

# ========================
# AUTH ROUTES
# ========================

# ---- SIGNUP ----
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data     = request.json
    email    = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    # Hash the password — never store plain text
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            'INSERT INTO users (email, password) VALUES (%s, %s) RETURNING id, email',
            (email, hashed.decode('utf-8'))
        )
        user = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
    except psycopg2.errors.UniqueViolation:
        return jsonify({'error': 'Email already exists'}), 409

    token = generate_token(user[0], user[1])
    return jsonify({
        'message': 'Account created successfully',
        'token': token,
        'email': user[1]
    }), 201

# ---- LOGIN ----
@app.route('/api/auth/login', methods=['POST'])
def login():
    data     = request.json
    email    = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    conn = get_db()
    cur  = conn.cursor()
    cur.execute('SELECT * FROM users WHERE email = %s', (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401

    # Check password against hashed version
    if not bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
        return jsonify({'error': 'Invalid email or password'}), 401

    token = generate_token(user[0], user[1])
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'email': user[1]
    })

# ========================
# TODO ROUTES
# ========================

# ---- GET ALL TODOS ----
@app.route('/api/todos', methods=['GET'])
@login_required
def get_todos():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute('''
        SELECT * FROM todos
        WHERE user_id = %s
        ORDER BY created_at DESC
    ''', (request.user_id,))
    todos = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([{
        'id':         t[0],
        'title':      t[2],
        'completed':  t[3],
        'created_at': str(t[4])
    } for t in todos])

# ---- CREATE A TODO ----
@app.route('/api/todos', methods=['POST'])
@login_required
def create_todo():
    data  = request.json
    title = data.get('title')

    if not title:
        return jsonify({'error': 'Title is required'}), 400

    conn = get_db()
    cur  = conn.cursor()
    cur.execute('''
        INSERT INTO todos (user_id, title)
        VALUES (%s, %s)
        RETURNING *
    ''', (request.user_id, title))
    todo = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({
        'id':        todo[0],
        'title':     todo[2],
        'completed': todo[3]
    }), 201

# ---- MARK TODO COMPLETE/INCOMPLETE ----
@app.route('/api/todos/<int:id>', methods=['PATCH'])
@login_required
def update_todo(id):
    data      = request.json
    completed = data.get('completed')

    conn = get_db()
    cur  = conn.cursor()
    cur.execute('''
        UPDATE todos
        SET completed = %s
        WHERE id = %s AND user_id = %s
        RETURNING *
    ''', (completed, id, request.user_id))
    todo = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    if not todo:
        return jsonify({'error': 'Todo not found'}), 404

    return jsonify({
        'id':        todo[0],
        'title':     todo[2],
        'completed': todo[3]
    })

# ---- DELETE A TODO ----
@app.route('/api/todos/<int:id>', methods=['DELETE'])
@login_required
def delete_todo(id):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute('''
        DELETE FROM todos
        WHERE id = %s AND user_id = %s
        RETURNING id
    ''', (id, request.user_id))
    deleted = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    if not deleted:
        return jsonify({'error': 'Todo not found'}), 404

    return jsonify({'message': f'Todo {id} deleted'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)