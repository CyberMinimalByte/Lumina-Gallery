import os
import sqlite3
import bcrypt
import uuid
import secrets
import time
import subprocess
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, g, send_from_directory
from functools import wraps

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ---------------------- Database ----------------------
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
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            verified INTEGER DEFAULT 0,
            shame INTEGER DEFAULT 0,
            banned_until TIMESTAMP,
            muted_until TIMESTAMP,
            avatar TEXT,
            bio TEXT,
            notify_new_comment INTEGER DEFAULT 1,
            notify_new_like INTEGER DEFAULT 1,
            notify_new_follower INTEGER DEFAULT 1
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            image_path TEXT NOT NULL,
            text TEXT,
            views INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            upload_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            value INTEGER NOT NULL,
            UNIQUE(upload_id, user_id),
            FOREIGN KEY (upload_id) REFERENCES uploads (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            upload_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            text TEXT NOT NULL,
            parent_id INTEGER DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (upload_id) REFERENCES uploads (id),
            FOREIGN KEY (parent_id) REFERENCES comments (id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            source_user_id INTEGER NOT NULL,
            source_username TEXT NOT NULL,
            upload_id INTEGER DEFAULT NULL,
            comment_id INTEGER DEFAULT NULL,
            read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (upload_id) REFERENCES uploads (id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS followers (
            user_id INTEGER NOT NULL,
            follower_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, follower_id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (follower_id) REFERENCES users (id)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS upload_limits (
            user_id INTEGER PRIMARY KEY,
            short_count INTEGER DEFAULT 0,
            last_short_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            daily_count INTEGER DEFAULT 0,
            last_daily_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS mod_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            moderator_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            target_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )''')
        # Admin
        admin = cursor.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        if not admin:
            hashed = bcrypt.hashpw('admin555111'.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO users (username, password, role, verified, avatar, bio) VALUES (?, ?, 'admin', 1, '', 'Главный админ')",
                           ('admin', hashed))
        # Demo user
        demo = cursor.execute("SELECT * FROM users WHERE username = 'demo_user'").fetchone()
        if not demo:
            hashed = bcrypt.hashpw('demo123'.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO users (username, password, role, verified, shame, avatar, bio) VALUES (?, ?, 'user', 0, 0, '', 'Демо-пользователь')",
                           ('demo_user', hashed))
        db.commit()

init_db()

# ---------------------- Helper functions ----------------------
def get_user_role(user_id):
    db = get_db()
    user = db.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    return user['role'] if user else 'user'

def is_banned(user_id):
    db = get_db()
    user = db.execute("SELECT banned_until FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or not user['banned_until']:
        return False
    banned_until = datetime.fromisoformat(user['banned_until'])
    return datetime.now() < banned_until

def is_muted(user_id):
    db = get_db()
    user = db.execute("SELECT muted_until FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or not user['muted_until']:
        return False
    muted_until = datetime.fromisoformat(user['muted_until'])
    return datetime.now() < muted_until

def check_mod_limit(moderator_id):
    db = get_db()
    three_hours_ago = (datetime.now() - timedelta(hours=3)).isoformat()
    count = db.execute("SELECT COUNT(*) as cnt FROM mod_actions WHERE moderator_id = ? AND created_at > ?",
                       (moderator_id, three_hours_ago)).fetchone()['cnt']
    return count < 12

def log_mod_action(moderator_id, action_type, target_id=None):
    db = get_db()
    db.execute("INSERT INTO mod_actions (moderator_id, action_type, target_id) VALUES (?, ?, ?)",
               (moderator_id, action_type, target_id))
    db.commit()

def add_notification(user_id, type, source_user_id, source_username, upload_id=None, comment_id=None):
    db = get_db()
    # Проверяем, включены ли уведомления такого типа у получателя
    user_settings = db.execute("SELECT notify_new_comment, notify_new_like, notify_new_follower FROM users WHERE id = ?", (user_id,)).fetchone()
    if type == 'comment' and not user_settings['notify_new_comment']:
        return
    if type == 'like' and not user_settings['notify_new_like']:
        return
    if type == 'follow' and not user_settings['notify_new_follower']:
        return
    db.execute('''INSERT INTO notifications (user_id, type, source_user_id, source_username, upload_id, comment_id)
                  VALUES (?, ?, ?, ?, ?, ?)''',
               (user_id, type, source_user_id, source_username, upload_id, comment_id))
    db.commit()

def check_short_limit(user_id):
    db = get_db()
    row = db.execute("SELECT short_count, last_short_reset FROM upload_limits WHERE user_id = ?", (user_id,)).fetchone()
    if not row:
        db.execute("INSERT INTO upload_limits (user_id, short_count, last_short_reset) VALUES (?, 0, ?)",
                   (user_id, datetime.now().isoformat()))
        return True, 10, 0
    last_reset = datetime.fromisoformat(row['last_short_reset'])
    now = datetime.now()
    if now - last_reset > timedelta(minutes=3):
        db.execute("UPDATE upload_limits SET short_count = 0, last_short_reset = ? WHERE user_id = ?",
                   (now.isoformat(), user_id))
        db.commit()
        return True, 10, 0
    remaining = 10 - row['short_count']
    if remaining > 0:
        return True, remaining, 0
    else:
        wait = int(180 - (now - last_reset).total_seconds())
        return False, 0, wait

def increment_short_count(user_id):
    db = get_db()
    db.execute("UPDATE upload_limits SET short_count = short_count + 1 WHERE user_id = ?", (user_id,))
    db.commit()

def check_daily_limit(user_id):
    db = get_db()
    row = db.execute("SELECT daily_count, last_daily_reset FROM upload_limits WHERE user_id = ?", (user_id,)).fetchone()
    if not row:
        db.execute("INSERT INTO upload_limits (user_id, daily_count, last_daily_reset) VALUES (?, 0, ?)",
                   (user_id, datetime.now().isoformat()))
        return True, 25
    last_reset = datetime.fromisoformat(row['last_daily_reset'])
    now = datetime.now()
    if now.date() > last_reset.date():
        db.execute("UPDATE upload_limits SET daily_count = 0, last_daily_reset = ? WHERE user_id = ?",
                   (now.isoformat(), user_id))
        db.commit()
        return True, 25
    remaining = 25 - row['daily_count']
    if remaining > 0:
        return True, remaining
    else:
        return False, 0

def increment_daily_count(user_id):
    db = get_db()
    db.execute("UPDATE upload_limits SET daily_count = daily_count + 1 WHERE user_id = ?", (user_id,))
    db.commit()

def is_name_blacklisted(name):
    db = get_db()
    row = db.execute("SELECT 1 FROM blacklist WHERE name = ?", (name,)).fetchone()
    return row is not None

def get_video_duration(filepath):
    try:
        cmd = ['ffprobe', '-v', 'error', '-show_entries', 'format=duration', '-of', 'default=noprint_wrappers=1:nokey=1', filepath]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=5).decode().strip()
        duration = float(output)
        return duration
    except:
        return None

# ---------------------- Auth decorators ----------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        role = get_user_role(session['user_id'])
        if role != 'admin':
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated

def moderator_or_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        role = get_user_role(session['user_id'])
        if role not in ('admin', 'moderator'):
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated

# ---------------------- Routes ----------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ----- Auth -----
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Missing fields'}), 400
    if is_name_blacklisted(username):
        return jsonify({'error': 'Это имя запрещено'}), 400
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        return jsonify({'error': 'User exists'}), 400
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    db.execute("INSERT INTO users (username, password, avatar, bio) VALUES (?, ?, ?, ?)",
               (username, hashed, '', ''))
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
    user = db.execute("SELECT id, username, password, role, verified, shame, banned_until, muted_until, avatar, bio FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    if user['banned_until']:
        banned_until = datetime.fromisoformat(user['banned_until'])
        if datetime.now() < banned_until:
            return jsonify({'error': f'Аккаунт забанен до {banned_until.strftime("%d.%m.%Y %H:%M")}'}), 403
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    session['verified'] = user['verified']
    session['shame'] = user['shame']
    session['avatar'] = user['avatar']
    session['bio'] = user['bio']
    session.pop('guest_upload_count', None)
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'verified': user['verified'],
        'shame': user['shame'],
        'banned_until': user['banned_until'],
        'muted_until': user['muted_until'],
        'avatar': user['avatar'],
        'bio': user['bio']
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/me', methods=['GET'])
def me():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    db = get_db()
    user = db.execute("SELECT id, username, role, verified, shame, banned_until, muted_until, avatar, bio FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'verified': user['verified'],
        'shame': user['shame'],
        'banned_until': user['banned_until'],
        'muted_until': user['muted_until'],
        'avatar': user['avatar'],
        'bio': user['bio']
    })

# ----- Uploads -----
@app.route('/api/uploads', methods=['GET'])
def get_uploads():
    db = get_db()
    uploads = db.execute('''SELECT u.*,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = 1) as likes,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = -1) as dislikes,
            (SELECT verified FROM users WHERE id = u.user_id) as username_verified,
            (SELECT shame FROM users WHERE id = u.user_id) as username_shame,
            (SELECT avatar FROM users WHERE id = u.user_id) as user_avatar
            FROM uploads u ORDER BY u.created_at DESC''').fetchall()
    return jsonify([dict(row) for row in uploads])

@app.route('/api/uploads', methods=['POST'])
def create_upload():
    is_guest = 'user_id' not in session
    if is_guest:
        guest_count = session.get('guest_upload_count', 0)
        if guest_count >= 2:
            return jsonify({'error': 'Гости могут загрузить только 2 файла. Зарегистрируйтесь для большего лимита.'}), 429
    else:
        if is_banned(session['user_id']):
            return jsonify({'error': 'Ваш аккаунт забанен'}), 403
        daily_ok, daily_remaining = check_daily_limit(session['user_id'])
        if not daily_ok:
            return jsonify({'error': f'Дневной лимит (25 файлов) исчерпан. Попробуйте завтра.'}), 429
        short_ok, short_remaining, wait = check_short_limit(session['user_id'])
        if not short_ok:
            return jsonify({'error': f'Лимит: вы загрузили 10 файлов за 3 минуты. Подождите {wait} секунд'}), 429

    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    text = request.form.get('text', '')
    if file.filename == '':
        return jsonify({'error': 'Empty file'}), 400

    ext = file.filename.rsplit('.', 1)[-1].lower()
    ALLOWED_IMAGE_EXT = ('jpg', 'jpeg', 'png', 'webp', 'gif')
    ALLOWED_VIDEO_EXT = ('mp4', 'webm', 'mov')
    if ext not in ALLOWED_IMAGE_EXT and ext not in ALLOWED_VIDEO_EXT:
        return jsonify({'error': 'Invalid format. Allowed: jpg, jpeg, png, webp, gif, mp4, webm, mov'}), 400

    if len(file.read()) > app.config['MAX_CONTENT_LENGTH']:
        return jsonify({'error': f'File too large (max {app.config["MAX_CONTENT_LENGTH"] // (1024*1024)} MB)'}), 400
    file.seek(0)

    if ext in ALLOWED_VIDEO_EXT:
        tmp_filename = f"{uuid.uuid4().hex}.{ext}"
        tmp_path = os.path.join(app.config['UPLOAD_FOLDER'], tmp_filename)
        file.save(tmp_path)
        duration = get_video_duration(tmp_path)
        if duration is not None and duration > 10.0:
            os.remove(tmp_path)
            return jsonify({'error': 'Видео не должно превышать 10 секунд'}), 400
        final_filename = tmp_filename
    else:
        final_filename = f"{uuid.uuid4().hex}.{ext}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], final_filename))

    db = get_db()
    if is_guest:
        guest_user = db.execute("SELECT id FROM users WHERE username = 'guest'").fetchone()
        if not guest_user:
            db.execute("INSERT INTO users (username, password, role) VALUES (?, '', 'guest')", ('guest',))
            db.commit()
            guest_user = db.execute("SELECT id FROM users WHERE username = 'guest'").fetchone()
        user_id = guest_user['id']
        username = "Гость"
        cursor = db.execute('''INSERT INTO uploads (user_id, username, image_path, text)
                               VALUES (?, ?, ?, ?)''',
                            (user_id, username, final_filename, text))
        session['guest_upload_count'] = session.get('guest_upload_count', 0) + 1
    else:
        cursor = db.execute('''INSERT INTO uploads (user_id, username, image_path, text)
                               VALUES (?, ?, ?, ?)''',
                            (session['user_id'], session['username'], final_filename, text))
        increment_short_count(session['user_id'])
        increment_daily_count(session['user_id'])

    upload_id = cursor.lastrowid
    db.commit()
    return jsonify({'id': upload_id, 'message': 'Uploaded'}), 201

@app.route('/api/uploads/<int:upload_id>', methods=['PUT'])
@login_required
def update_upload(upload_id):
    data = request.get_json()
    new_text = data.get('text', '').strip()
    db = get_db()
    upload = db.execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()
    if not upload:
        return jsonify({'error': 'Not found'}), 404
    role = get_user_role(session['user_id'])
    if not (role == 'admin' or upload['user_id'] == session['user_id']):
        return jsonify({'error': 'Forbidden'}), 403
    db.execute("UPDATE uploads SET text = ? WHERE id = ?", (new_text, upload_id))
    db.commit()
    return jsonify({'message': 'Updated'})

@app.route('/api/uploads/<int:upload_id>', methods=['DELETE'])
@login_required
def delete_upload(upload_id):
    db = get_db()
    upload = db.execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()
    if not upload:
        return jsonify({'error': 'Not found'}), 404
    role = get_user_role(session['user_id'])
    if role == 'admin':
        pass
    elif role == 'moderator':
        if not check_mod_limit(session['user_id']):
            return jsonify({'error': 'Превышен лимит действий модератора (12 за 3 часа)'}), 429
        log_mod_action(session['user_id'], 'delete_photo', upload_id)
    elif upload['user_id'] == session['user_id']:
        pass
    else:
        return jsonify({'error': 'Forbidden'}), 403
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], upload['image_path']))
    except:
        pass
    db.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))
    db.execute("DELETE FROM likes WHERE upload_id = ?", (upload_id,))
    db.execute("DELETE FROM comments WHERE upload_id = ?", (upload_id,))
    db.execute("DELETE FROM notifications WHERE upload_id = ?", (upload_id,))
    db.commit()
    return jsonify({'message': 'Deleted'})

@app.route('/api/uploads/<int:upload_id>/view', methods=['POST'])
def increment_views(upload_id):
    db = get_db()
    db.execute("UPDATE uploads SET views = views + 1 WHERE id = ?", (upload_id,))
    db.commit()
    return jsonify({'message': 'OK'})

# ----- Likes -----
@app.route('/api/uploads/<int:upload_id>/like', methods=['POST'])
@login_required
def like_upload(upload_id):
    if is_muted(session['user_id']):
        return jsonify({'error': 'Вы заглушены и не можете ставить лайки'}), 403
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
    upload = db.execute("SELECT user_id FROM uploads WHERE id = ?", (upload_id,)).fetchone()
    if upload and upload['user_id'] != session['user_id']:
        add_notification(upload['user_id'], 'like' if value == 1 else 'dislike',
                         session['user_id'], session['username'], upload_id)
    return jsonify({'likes': likes, 'dislikes': dislikes})

# ----- Comments -----
@app.route('/api/uploads/<int:upload_id>/comments', methods=['GET'])
def get_comments(upload_id):
    db = get_db()
    comments = db.execute('''SELECT c.*, u.avatar as user_avatar FROM comments c
                             LEFT JOIN users u ON c.user_id = u.id
                             WHERE c.upload_id = ? ORDER BY c.created_at ASC''', (upload_id,)).fetchall()
    return jsonify([dict(row) for row in comments])

@app.route('/api/uploads/<int:upload_id>/comments', methods=['POST'])
@login_required
def add_comment(upload_id):
    if is_muted(session['user_id']):
        return jsonify({'error': 'Вы заглушены и не можете писать комментарии'}), 403
    data = request.get_json()
    text = data.get('text', '').strip()
    parent_id = data.get('parent_id', None)
    if not text:
        return jsonify({'error': 'Empty comment'}), 400
    db = get_db()
    cursor = db.execute('''INSERT INTO comments (upload_id, user_id, username, text, parent_id)
                           VALUES (?, ?, ?, ?, ?)''',
                        (upload_id, session['user_id'], session['username'], text, parent_id))
    comment_id = cursor.lastrowid
    db.commit()
    upload = db.execute("SELECT user_id FROM uploads WHERE id = ?", (upload_id,)).fetchone()
    if upload and upload['user_id'] != session['user_id']:
        add_notification(upload['user_id'], 'comment', session['user_id'], session['username'], upload_id, comment_id)
    if parent_id:
        parent = db.execute("SELECT user_id FROM comments WHERE id = ?", (parent_id,)).fetchone()
        if parent and parent['user_id'] != session['user_id']:
            add_notification(parent['user_id'], 'reply', session['user_id'], session['username'], upload_id, comment_id)
    comment = db.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()
    return jsonify(dict(comment)), 201

@app.route('/api/comments/<int:comment_id>', methods=['DELETE'])
@login_required
def delete_comment(comment_id):
    db = get_db()
    comment = db.execute("SELECT * FROM comments WHERE id = ?", (comment_id,)).fetchone()
    if not comment:
        return jsonify({'error': 'Not found'}), 404
    role = get_user_role(session['user_id'])
    if role == 'admin':
        pass
    elif role == 'moderator':
        if not check_mod_limit(session['user_id']):
            return jsonify({'error': 'Превышен лимит действий модератора (12 за 3 часа)'}), 429
        log_mod_action(session['user_id'], 'delete_comment', comment_id)
    elif comment['user_id'] == session['user_id']:
        pass
    else:
        return jsonify({'error': 'Forbidden'}), 403
    db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    db.execute("DELETE FROM notifications WHERE comment_id = ?", (comment_id,))
    db.commit()
    return jsonify({'message': 'Deleted'})

# ----- Notifications -----
@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    db = get_db()
    notifs = db.execute('''SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50''',
                        (session['user_id'],)).fetchall()
    db.execute("UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0", (session['user_id'],))
    db.commit()
    return jsonify([dict(row) for row in notifs])

@app.route('/api/notifications/unread', methods=['GET'])
@login_required
def unread_count():
    db = get_db()
    cnt = db.execute("SELECT COUNT(*) as cnt FROM notifications WHERE user_id = ? AND read = 0",
                     (session['user_id'],)).fetchone()['cnt']
    return jsonify({'count': cnt})

# ----- Profile & Followers -----
@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user_profile(user_id):
    db = get_db()
    user = db.execute("SELECT id, username, role, verified, shame, avatar, bio FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    # Статистика
    uploads_count = db.execute("SELECT COUNT(*) as cnt FROM uploads WHERE user_id = ?", (user_id,)).fetchone()['cnt']
    followers_count = db.execute("SELECT COUNT(*) as cnt FROM followers WHERE user_id = ?", (user_id,)).fetchone()['cnt']
    following_count = db.execute("SELECT COUNT(*) as cnt FROM followers WHERE follower_id = ?", (user_id,)).fetchone()['cnt']
    # Подписан ли текущий пользователь
    is_following = False
    if 'user_id' in session:
        check = db.execute("SELECT 1 FROM followers WHERE user_id = ? AND follower_id = ?", (user_id, session['user_id'])).fetchone()
        is_following = bool(check)
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'verified': user['verified'],
        'shame': user['shame'],
        'avatar': user['avatar'],
        'bio': user['bio'],
        'uploads_count': uploads_count,
        'followers_count': followers_count,
        'following_count': following_count,
        'is_following': is_following
    })

@app.route('/api/user/<int:user_id>/follow', methods=['POST'])
@login_required
def follow_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot follow yourself'}), 400
    db = get_db()
    # Проверяем, не подписан ли уже
    existing = db.execute("SELECT 1 FROM followers WHERE user_id = ? AND follower_id = ?", (user_id, session['user_id'])).fetchone()
    if existing:
        # Если уже подписан — отписываемся
        db.execute("DELETE FROM followers WHERE user_id = ? AND follower_id = ?", (user_id, session['user_id']))
        db.commit()
        return jsonify({'following': False})
    else:
        db.execute("INSERT INTO followers (user_id, follower_id) VALUES (?, ?)", (user_id, session['user_id']))
        db.commit()
        # Уведомление о новой подписке
        add_notification(user_id, 'follow', session['user_id'], session['username'])
        return jsonify({'following': True})

@app.route('/api/user/<int:user_id>/feed', methods=['GET'])
@login_required
def user_feed(user_id):
    """Лента из загрузок тех, на кого подписан пользователь"""
    db = get_db()
    uploads = db.execute('''SELECT u.*,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = 1) as likes,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = -1) as dislikes,
            (SELECT verified FROM users WHERE id = u.user_id) as username_verified,
            (SELECT shame FROM users WHERE id = u.user_id) as username_shame,
            (SELECT avatar FROM users WHERE id = u.user_id) as user_avatar
            FROM uploads u
            WHERE u.user_id IN (SELECT follower_id FROM followers WHERE user_id = ?)
            ORDER BY u.created_at DESC''', (user_id,)).fetchall()
    return jsonify([dict(row) for row in uploads])

@app.route('/api/user/<int:user_id>/uploads', methods=['GET'])
def get_user_uploads(user_id):
    db = get_db()
    uploads = db.execute('''SELECT u.*,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = 1) as likes,
            (SELECT COUNT(*) FROM likes WHERE upload_id = u.id AND value = -1) as dislikes,
            (SELECT verified FROM users WHERE id = u.user_id) as username_verified,
            (SELECT shame FROM users WHERE id = u.user_id) as username_shame,
            (SELECT avatar FROM users WHERE id = u.user_id) as user_avatar
            FROM uploads u WHERE u.user_id = ? ORDER BY u.created_at DESC''', (user_id,)).fetchall()
    return jsonify([dict(row) for row in uploads])

# ----- Settings -----
@app.route('/api/settings', methods=['GET'])
@login_required
def get_settings():
    db = get_db()
    user = db.execute("SELECT username, avatar, bio, notify_new_comment, notify_new_like, notify_new_follower FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    return jsonify(dict(user))

@app.route('/api/settings/avatar', methods=['POST'])
@login_required
def update_avatar():
    if 'avatar' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'error': 'Empty file'}), 400
    ext = file.filename.rsplit('.', 1)[-1].lower()
    if ext not in ('jpg', 'jpeg', 'png', 'webp', 'gif'):
        return jsonify({'error': 'Invalid format'}), 400
    if len(file.read()) > 2 * 1024 * 1024:  # 2 MB
        return jsonify({'error': 'Avatar too large (max 2MB)'}), 400
    file.seek(0)
    filename = f"avatar_{session['user_id']}_{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    db = get_db()
    db.execute("UPDATE users SET avatar = ? WHERE id = ?", (filename, session['user_id']))
    db.commit()
    session['avatar'] = filename
    return jsonify({'avatar': filename})

@app.route('/api/settings/bio', methods=['PUT'])
@login_required
def update_bio():
    data = request.get_json()
    bio = data.get('bio', '').strip()[:500]  # ограничим длину
    db = get_db()
    db.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, session['user_id']))
    db.commit()
    session['bio'] = bio
    return jsonify({'bio': bio})

@app.route('/api/settings/password', methods=['PUT'])
@login_required
def update_password():
    data = request.get_json()
    old = data.get('old_password')
    new = data.get('new_password')
    if not old or not new:
        return jsonify({'error': 'Missing fields'}), 400
    db = get_db()
    user = db.execute("SELECT password FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    if not bcrypt.checkpw(old.encode('utf-8'), user['password']):
        return jsonify({'error': 'Wrong old password'}), 403
    hashed = bcrypt.hashpw(new.encode('utf-8'), bcrypt.gensalt())
    db.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, session['user_id']))
    db.commit()
    return jsonify({'message': 'Password updated'})

@app.route('/api/settings/notifications', methods=['PUT'])
@login_required
def update_notification_settings():
    data = request.get_json()
    notify_new_comment = data.get('notify_new_comment', 1)
    notify_new_like = data.get('notify_new_like', 1)
    notify_new_follower = data.get('notify_new_follower', 1)
    db = get_db()
    db.execute("UPDATE users SET notify_new_comment = ?, notify_new_like = ?, notify_new_follower = ? WHERE id = ?",
               (notify_new_comment, notify_new_like, notify_new_follower, session['user_id']))
    db.commit()
    return jsonify({'message': 'Settings updated'})

# ----- Admin / Moderation -----
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def list_users():
    db = get_db()
    users = db.execute("SELECT id, username, role, verified, shame, banned_until, muted_until, avatar, bio FROM users").fetchall()
    return jsonify([dict(row) for row in users])

@app.route('/api/admin/users/<int:user_id>/role', methods=['POST'])
@admin_required
def set_user_role(user_id):
    data = request.get_json()
    new_role = data.get('role')
    if new_role not in ('admin', 'moderator', 'user'):
        return jsonify({'error': 'Invalid role'}), 400
    if user_id == session['user_id'] and new_role != 'admin':
        return jsonify({'error': 'Cannot demote yourself'}), 403
    db = get_db()
    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()
    return jsonify({'message': 'Role updated'})

@app.route('/api/admin/users/<int:user_id>/ban', methods=['POST'])
@admin_required
def ban_user(user_id):
    data = request.get_json()
    duration_hours = data.get('hours', 24)
    banned_until = (datetime.now() + timedelta(hours=duration_hours)).isoformat()
    db = get_db()
    db.execute("UPDATE users SET banned_until = ? WHERE id = ?", (banned_until, user_id))
    db.commit()
    return jsonify({'banned_until': banned_until})

@app.route('/api/admin/users/<int:user_id>/mute', methods=['POST'])
@admin_required
def mute_user(user_id):
    data = request.get_json()
    duration_hours = data.get('hours', 24)
    muted_until = (datetime.now() + timedelta(hours=duration_hours)).isoformat()
    db = get_db()
    db.execute("UPDATE users SET muted_until = ? WHERE id = ?", (muted_until, user_id))
    db.commit()
    return jsonify({'muted_until': muted_until})

@app.route('/api/admin/users/<int:user_id>/unban', methods=['POST'])
@admin_required
def unban_user(user_id):
    db = get_db()
    db.execute("UPDATE users SET banned_until = NULL WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({'message': 'Unbanned'})

@app.route('/api/admin/users/<int:user_id>/unmute', methods=['POST'])
@admin_required
def unmute_user(user_id):
    db = get_db()
    db.execute("UPDATE users SET muted_until = NULL WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({'message': 'Unmuted'})

@app.route('/api/admin/users/<int:user_id>/verify', methods=['POST'])
@admin_required
def verify_user(user_id):
    db = get_db()
    user = db.execute("SELECT verified FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    new_status = 1 if not user['verified'] else 0
    db.execute("UPDATE users SET verified = ? WHERE id = ?", (new_status, user_id))
    db.commit()
    return jsonify({'verified': new_status})

@app.route('/api/admin/users/<int:user_id>/shame', methods=['POST'])
@admin_required
def toggle_shame(user_id):
    db = get_db()
    user = db.execute("SELECT shame FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    new_status = 1 if not user['shame'] else 0
    db.execute("UPDATE users SET shame = ? WHERE id = ?", (new_status, user_id))
    db.commit()
    return jsonify({'shame': new_status})

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
    db.execute("DELETE FROM notifications WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM followers WHERE user_id = ? OR follower_id = ?", (user_id, user_id))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({'message': 'User deleted'})

@app.route('/api/admin/blacklist', methods=['GET'])
@admin_required
def get_blacklist():
    db = get_db()
    names = db.execute("SELECT name FROM blacklist").fetchall()
    return jsonify([row['name'] for row in names])

@app.route('/api/admin/blacklist', methods=['POST'])
@admin_required
def add_blacklist():
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Empty name'}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO blacklist (name) VALUES (?)", (name,))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Name already in blacklist'}), 400
    return jsonify({'message': 'Added'})

@app.route('/api/admin/blacklist/<name>', methods=['DELETE'])
@admin_required
def remove_blacklist(name):
    db = get_db()
    db.execute("DELETE FROM blacklist WHERE name = ?", (name,))
    db.commit()
    return jsonify({'message': 'Removed'})

@app.route('/api/activities', methods=['GET'])
@login_required
def get_activities():
    db = get_db()
    notifs = db.execute('''SELECT * FROM notifications WHERE user_id = ? AND read = 0
                           ORDER BY created_at DESC LIMIT 10''',
                        (session['user_id'],)).fetchall()
    return jsonify([dict(row) for row in notifs])

# ---------------------- Сезонные ивенты ----------------------
current_event = {
    'name': 'default',  # default, winter, summer, rain, disco, halloween
    'active': False,
    'set_by': None,
    'set_at': None
}

@app.route('/api/event/set', methods=['POST'])
def set_event():
    """Установить ивент (доступно только админу)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    role = get_user_role(session['user_id'])
    if role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    
    data = request.get_json()
    event_name = data.get('event', 'default')
    duration = data.get('duration', 0)  # 0 = бесконечно, или число секунд
    
    global current_event
    current_event = {
        'name': event_name,
        'active': True,
        'set_by': session['username'],
        'set_at': time.time(),
        'duration': duration
    }
    
    return jsonify({'event': event_name, 'duration': duration})

@app.route('/api/event/get', methods=['GET'])
def get_event():
    """Получить текущий ивент"""
    global current_event
    
    # Проверяем, не истекло ли время
    if current_event['active'] and current_event['duration'] > 0:
        if time.time() - current_event['set_at'] > current_event['duration']:
            current_event = {'name': 'default', 'active': False, 'set_by': None, 'set_at': None, 'duration': 0}
    
    return jsonify({
        'event': current_event['name'],
        'active': current_event['active']
    })

@app.route('/api/event/off', methods=['POST'])
def off_event():
    """Выключить ивент (доступно только админу)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    role = get_user_role(session['user_id'])
    if role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    
    global current_event
    current_event = {'name': 'default', 'active': False, 'set_by': None, 'set_at': None, 'duration': 0}
    
    return jsonify({'message': 'Event disabled'})

# ---------------------- Секретный эндпоинт для приколов ----------------------
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(16))
# Храним последнее сообщение (в памяти — сбросится при перезапуске, но для прикола хватит)
last_prank_message = None
last_prank_time = None

@app.route('/api/prank/set', methods=['POST'])
def set_prank():
    """Установить сообщение для показа на сайте (доступно только админу)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    role = get_user_role(session['user_id'])
    if role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    
    data = request.get_json()
    message = data.get('message', '')
    duration = data.get('duration', 5)  # сколько секунд показывать
    
    global last_prank_message, last_prank_time
    last_prank_message = message
    last_prank_time = time.time() + duration
    
    return jsonify({'message': 'Prank set', 'duration': duration})

@app.route('/api/prank/get', methods=['GET'])
def get_prank():
    """Получить текущее сообщение (для фронта)"""
    global last_prank_message, last_prank_time
    
    if last_prank_message and last_prank_time and time.time() < last_prank_time:
        return jsonify({'message': last_prank_message, 'active': True})
    else:
        # Сбрасываем, если время вышло
        last_prank_message = None
        last_prank_time = None
        return jsonify({'message': None, 'active': False})

if __name__ == '__main__':
    app.run(debug=True)