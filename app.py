import os
import sqlite3
import bcrypt
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, g, send_from_directory
from functools import wraps
import secrets

app = Flask(__name__, static_folder='static', template_folder='templates')
# Используем секретный ключ из переменной окружения или генерируем
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['UPLOAD_FOLDER'] = 'uploads'
# Создаём папку uploads, если её нет
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database helper
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('gallery.db')
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # Users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )''')
        # Uploads table
        cursor.execute('''CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            image_path TEXT NOT NULL,
            text TEXT,
            approved INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        # Likes table
        cursor.execute('''CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            upload_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            value INTEGER NOT NULL,
            UNIQUE(upload_id, user_id),
            FOREIGN KEY (upload_id) REFERENCES uploads (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        # Comments table
        cursor.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            upload_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (upload_id) REFERENCES uploads (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        # Insert admin if not exists
        admin = cursor.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        if not admin:
            hashed = bcrypt.hashpw('admin555111'.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                           ('admin', hashed))
        # Insert demo user if not exists
        demo = cursor.execute("SELECT * FROM users WHERE username = 'demo_user'").fetchone()
        if not demo:
            hashed = bcrypt.hashpw('demo123'.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
                           ('demo_user', hashed))
        db.commit()

init_db()

# Auth decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        db = get_db()
        user = db.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        if not user or not user['is_admin']:
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

# Serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# API endpoints
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Missing fields'}), 400
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        return jsonify({'error': 'User exists'}), 400
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
    db.commit()
    return jsonify({'message': 'Registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Missing fields'}), 400
    db = get_db()
    user = db.execute("SELECT id, username, password, is_admin FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['is_admin'] = user['is_admin']
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'is_admin': user['is_admin']
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/me', methods=['GET'])
def me():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify({
        'id': session['user_id'],
        'username': session['username'],
        'is_admin': session['is_admin']
    })

@app.route('/api/uploads', methods=['GET'])
def get_uploads():
    db = get_db()
    is_admin = session.get('is_admin', False)
    if is_admin:
        uploads = db.execute('''SELECT u.*, 
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = 1) as likes,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = -1) as dislikes
            FROM uploads u ORDER BY u.created_at DESC''').fetchall()
    else:
        uploads = db.execute('''SELECT u.*, 
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = 1) as likes,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = -1) as dislikes
            FROM uploads u WHERE u.approved = 1 ORDER BY u.created_at DESC''').fetchall()
    return jsonify([dict(row) for row in uploads])

@app.route('/api/uploads', methods=['POST'])
@login_required
def create_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    text = request.form.get('text', '')
    if file.filename == '':
        return jsonify({'error': 'Empty file'}), 400
    # Save file
    ext = file.filename.rsplit('.', 1)[-1].lower()
    if ext not in ('jpg', 'jpeg', 'png', 'webp'):
        return jsonify({'error': 'Invalid format'}), 400
    filename = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    # Determine approval status
    approved = 1 if session['is_admin'] else 0
    db = get_db()
    cursor = db.execute('''INSERT INTO uploads (user_id, username, image_path, text, approved)
                           VALUES (?, ?, ?, ?, ?)''',
                        (session['user_id'], session['username'], filename, text, approved))
    db.commit()
    return jsonify({'id': cursor.lastrowid, 'message': 'Uploaded'}), 201

@app.route('/api/uploads/<int:upload_id>', methods=['DELETE'])
@login_required
def delete_upload(upload_id):
    db = get_db()
    upload = db.execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()
    if not upload:
        return jsonify({'error': 'Not found'}), 404
    if not (session['is_admin'] or upload['user_id'] == session['user_id']):
        return jsonify({'error': 'Forbidden'}), 403
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], upload['image_path']))
    except:
        pass
    db.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))
    db.execute("DELETE FROM likes WHERE upload_id = ?", (upload_id,))
    db.execute("DELETE FROM comments WHERE upload_id = ?", (upload_id,))
    db.commit()
    return jsonify({'message': 'Deleted'})

@app.route('/api/uploads/<int:upload_id>/approve', methods=['POST'])
@admin_required
def approve_upload(upload_id):
    db = get_db()
    db.execute("UPDATE uploads SET approved = 1 WHERE id = ?", (upload_id,))
    db.commit()
    return jsonify({'message': 'Approved'})

@app.route('/api/uploads/<int:upload_id>/like', methods=['POST'])
@login_required
def like_upload(upload_id):
    data = request.get_json()
    value = data.get('value')
    if value not in (1, -1, 0):
        return jsonify({'error': 'Invalid value'}), 400
    db = get_db()
    existing = db.execute("SELECT * FROM likes WHERE upload_id = ? AND user_id = ?",
                          (upload_id, session['user_id'])).fetchone()
    if value == 0:
        if existing:
            db.execute("DELETE FROM likes WHERE upload_id = ? AND user_id = ?",
                       (upload_id, session['user_id']))
    else:
        if existing:
            db.execute("UPDATE likes SET value = ? WHERE upload_id = ? AND user_id = ?",
                       (value, upload_id, session['user_id']))
        else:
            db.execute("INSERT INTO likes (upload_id, user_id, value) VALUES (?, ?, ?)",
                       (upload_id, session['user_id'], value))
    db.commit()
    likes = db.execute("SELECT COUNT(*) as cnt FROM likes WHERE upload_id = ? AND value = 1",
                       (upload_id,)).fetchone()['cnt']
    dislikes = db.execute("SELECT COUNT(*) as cnt FROM likes WHERE upload_id = ? AND value = -1",
                          (upload_id,)).fetchone()['cnt']
    return jsonify({'likes': likes, 'dislikes': dislikes})

@app.route('/api/uploads/<int:upload_id>/comments', methods=['GET'])
def get_comments(upload_id):
    db = get_db()
    comments = db.execute('''SELECT * FROM comments WHERE upload_id = ? ORDER BY created_at DESC''',
                          (upload_id,)).fetchall()
    return jsonify([dict(row) for row in comments])

@app.route('/api/uploads/<int:upload_id>/comments', methods=['POST'])
@login_required
def add_comment(upload_id):
    data = request.get_json()
    text = data.get('text', '').strip()
    if not text:
        return jsonify({'error': 'Empty comment'}), 400
    db = get_db()
    db.execute('''INSERT INTO comments (upload_id, user_id, username, text)
                  VALUES (?, ?, ?, ?)''',
               (upload_id, session['user_id'], session['username'], text))
    db.commit()
    comment_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    comment = db.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()
    return jsonify(dict(comment)), 201

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def list_users():
    db = get_db()
    users = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return jsonify([dict(row) for row in users])

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 403
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    uploads = db.execute("SELECT image_path FROM uploads WHERE user_id = ?", (user_id,)).fetchall()
    for up in uploads:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], up['image_path']))
        except:
            pass
    db.execute("DELETE FROM uploads WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM likes WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM comments WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({'message': 'User deleted'})

@app.route('/api/admin/pending', methods=['GET'])
@admin_required
def pending_uploads():
    db = get_db()
    pending = db.execute('''SELECT * FROM uploads WHERE approved = 0 ORDER BY created_at DESC''').fetchall()
    return jsonify([dict(row) for row in pending])

if __name__ == '__main__':
    # Для локального запуска
    app.run(debug=True)
    
# Для продакшена на Render используйте gunicorn:
# gunicorn app:app