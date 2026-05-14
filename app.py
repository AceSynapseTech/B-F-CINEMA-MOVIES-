from flask import Flask, request, jsonify, session, send_from_directory, redirect, send_file, Response
from flask_cors import CORS
import boto3
import os
import sqlite3
from datetime import datetime, timedelta
import hashlib
import json
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import traceback
import uuid
from botocore.exceptions import ClientError
import mimetypes
from io import BytesIO
import time
import re
from decimal import Decimal
import base64
import requests
import schedule
import threading
import atexit
import shutil

# =========== IMPORTS ===========
try:
    import segno
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

# =========== DATABASE & STORAGE PATHS ===========
def get_persistent_path(filename):
    """Get persistent path that survives server restarts"""
    if os.getenv('RENDER', 'false').lower() == 'true':
        data_dir = '/data'
        os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, filename)
    else:
        return filename

def get_db_path():
    return get_persistent_path('bfcinema.db')

def get_upload_dir():
    upload_dir = get_persistent_path('uploads')
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir

def get_temp_dir():
    temp_dir = get_persistent_path('temp_uploads')
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', static_url_path='')

RENDER = os.getenv('RENDER', 'false').lower() == 'true'

app.secret_key = os.getenv('SECRET_KEY', 'bfcinema_secret_key_2026_secure_12345_prod_change_me')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 31536000
app.config['MAX_CONTENT_LENGTH'] = 900 * 1024 * 1024

# Configure CORS
if RENDER:
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    
    RENDER_EXTERNAL_URL = os.getenv('RENDER_EXTERNAL_URL', '')
    allowed_origins = [
        RENDER_EXTERNAL_URL,
        'https://bfcinema.onrender.com',
        'http://localhost:5000',
        'http://127.0.0.1:5000',
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://localhost:5500',
        'http://127.0.0.1:5500'
    ]
    allowed_origins = [origin for origin in allowed_origins if origin]
else:
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = False
    
    allowed_origins = [
        'http://localhost:5000',
        'http://127.0.0.1:5000',
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://localhost:5500',
        'http://127.0.0.1:5500'
    ]

CORS(app, 
     origins=allowed_origins,
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'Accept', 'Range', 'X-Requested-With'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
     expose_headers=['Content-Type', 'Authorization', 'Content-Range', 'Accept-Ranges', 'Content-Length'])

# =========== BACKBLAZE B2 CONFIGURATION ===========
BACKBLAZE_CONFIG = {
    'key_id': os.getenv('BACKBLAZE_KEY_ID', '0033811f85f980c0000000001'),
    'application_key': os.getenv('BACKBLAZE_APPLICATION_KEY', 'K003ROCPq4vNmTQXZx9h4fZ0ozcFzVM'),
    'bucket': os.getenv('BACKBLAZE_BUCKET', 'bfcinema'),
    'endpoint': os.getenv('BACKBLAZE_ENDPOINT', 'https://s3.eu-central-003.backblazeb2.com')
}

s3_client = None
try:
    s3_client = boto3.client(
        's3',
        endpoint_url=BACKBLAZE_CONFIG['endpoint'],
        aws_access_key_id=BACKBLAZE_CONFIG['key_id'],
        aws_secret_access_key=BACKBLAZE_CONFIG['application_key'],
        config=boto3.session.Config(signature_version='s3v4')
    )
    logger.info("✅ Backblaze B2 S3 client initialized successfully")
    response = s3_client.list_buckets()
    logger.info(f"✅ Connected to Backblaze B2. Buckets: {[b['Name'] for b in response['Buckets']]}")
except Exception as e:
    logger.error(f"❌ Failed to initialize Backblaze B2 S3 client: {str(e)}")

# =========== DATABASE INITIALIZATION (No STK Push tables) ===========
def init_db():
    try:
        db_path = get_db_path()
        logger.info(f"📂 Initializing persistent database at: {db_path}")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        
        # Movies table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS movies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                year INTEGER,
                duration TEXT,
                video_key TEXT NOT NULL,
                poster_key TEXT,
                uploaded_by TEXT DEFAULT 'Admin',
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                views INTEGER DEFAULT 0,
                download_count INTEGER DEFAULT 0,
                storage TEXT DEFAULT 'backblaze',
                is_active BOOLEAN DEFAULT 1,
                file_size INTEGER DEFAULT 0,
                file_type TEXT DEFAULT 'video/mp4',
                free_preview BOOLEAN DEFAULT 0,
                s3_url TEXT,
                stream_url TEXT,
                price DECIMAL(10,2) DEFAULT 30.00
            )
        """)
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT,
                password_hash TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                movies_watched INTEGER DEFAULT 0,
                downloads INTEGER DEFAULT 0,
                downloads_list TEXT DEFAULT '[]',
                last_login TIMESTAMP
            )
        """)
        
        # Transactions table (simplified - no STK Push columns)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_code TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                user_email TEXT NOT NULL,
                user_phone TEXT NOT NULL,
                movie_id INTEGER NOT NULL,
                movie_title TEXT NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                payment_date TEXT,
                payment_time TEXT,
                status TEXT DEFAULT 'verified',
                verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE
            )
        """)
        
        # Downloads table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                movie_id INTEGER,
                downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                movie_data TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE
            )
        """)
        
        # Activity log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                user_email TEXT,
                action TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Watch history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS watch_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                movie_id INTEGER,
                watched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE
            )
        """)
        
        # User access table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                movie_id INTEGER NOT NULL,
                transaction_id INTEGER,
                access_granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE,
                FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE SET NULL
            )
        """)
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_transaction_code ON transactions(transaction_code)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_transactions ON transactions(user_id, created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_access ON user_access(user_id, movie_id, is_active)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_movie_expires ON movies(expires_at, is_active)')
        
        # Check if admin user exists
        cursor.execute('SELECT * FROM users WHERE email = ?', ('BFCM2026@GMAIL.COM',))
        admin_exists = cursor.fetchone()
        
        if not admin_exists:
            admin_password = os.getenv('ADMIN_PASSWORD', 'ASGWG2@##...')
            password_hash = generate_password_hash(admin_password)
            cursor.execute('''
                INSERT INTO users (name, email, phone, password_hash, is_admin)
                VALUES (?, ?, ?, ?, ?)
            ''', ('Administrator', 'BFCM2026@GMAIL.COM', '+254 700 505325', password_hash, 1))
            logger.info("✅ Admin user created")
        else:
            logger.info("✅ Admin user already exists")
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Database initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Database initialization error: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def get_db():
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def row_to_dict(row):
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}

# =========== INITIALIZE ===========
print("="*60)
print("🎬 B/F Cinema - Starting Database Initialization")
print("="*60)

os.makedirs(get_upload_dir(), exist_ok=True)
os.makedirs(get_temp_dir(), exist_ok=True)

if init_db():
    print("✅ Database initialized successfully")
else:
    print("❌ Database initialization failed")

print(f"📁 Database: {get_db_path()}")
print(f"📁 Uploads: {get_upload_dir()}")
print(f"📁 Temp: {get_temp_dir()}")
print(f"☁️  Backblaze B2: {'✅ Connected' if s3_client else '❌ Not Connected'}")
print("="*60)

def backup_database():
    try:
        source_path = get_db_path()
        if os.path.exists(source_path):
            backup_path = f"{source_path}.backup"
            shutil.copy2(source_path, backup_path)
            logger.info(f"📁 Database backed up to: {backup_path}")
            return True
        return False
    except Exception as e:
        logger.error(f"❌ Backup failed: {str(e)}")
        return False

backup_database()

# =========== HELPER FUNCTIONS ===========
def generate_presigned_url(key, expires=7200):
    if not s3_client or not key:
        logger.warning(f"S3 client not available or key empty: {key}")
        return None
    
    try:
        content_type = 'video/mp4'
        key_lower = key.lower()
        if key_lower.endswith(('.mp4', '.m4v', '.mp4v')):
            content_type = 'video/mp4'
        elif key_lower.endswith('.avi'):
            content_type = 'video/x-msvideo'
        elif key_lower.endswith('.mov'):
            content_type = 'video/quicktime'
        elif key_lower.endswith('.mkv'):
            content_type = 'video/x-matroska'
        elif key_lower.endswith('.webm'):
            content_type = 'video/webm'
        elif key_lower.endswith('.flv'):
            content_type = 'video/x-flv'
        elif key_lower.endswith('.wmv'):
            content_type = 'video/x-ms-wmv'
        elif key_lower.endswith('.mpg') or key_lower.endswith('.mpeg'):
            content_type = 'video/mpeg'
        elif key_lower.endswith(('.jpg', '.jpeg')):
            content_type = 'image/jpeg'
        elif key_lower.endswith('.png'):
            content_type = 'image/png'
        elif key_lower.endswith('.gif'):
            content_type = 'image/gif'
        elif key_lower.endswith('.webp'):
            content_type = 'image/webp'
        
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': BACKBLAZE_CONFIG['bucket'],
                'Key': key,
                'ResponseContentType': content_type,
                'ResponseContentDisposition': 'inline',
                'ResponseCacheControl': 'max-age=7200, public'
            },
            ExpiresIn=expires,
            HttpMethod='GET'
        )
        return url
    except Exception as e:
        logger.error(f"❌ Presigned URL error for key {key}: {str(e)}")
        return None

def log_activity(user_id, user_email, action, details=None):
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        details_str = json.dumps(details) if details else '{}'
        cursor.execute('''
            INSERT INTO activity_log (user_id, user_email, action, details)
            VALUES (?, ?, ?, ?)
        ''', (str(user_id), user_email, action, details_str))
        conn.commit()
    except Exception as e:
        logger.error(f"Activity log error: {str(e)}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== AUTO-DELETION FUNCTIONS ===========
def calculate_expiry_date():
    return datetime.now() + timedelta(days=300)

def delete_expired_movies():
    deleted_count = 0
    conn = None
    cursor = None
    try:
        logger.info("🔍 Checking for expired movies to delete...")
        conn = get_db()
        cursor = conn.cursor()
        now = datetime.now()
        cursor.execute('''
            SELECT id, title, video_key, poster_key, uploaded_at, expires_at 
            FROM movies 
            WHERE expires_at IS NOT NULL AND expires_at < ? AND is_active = 1
        ''', (now,))
        expired_movies = cursor.fetchall()
        if expired_movies:
            logger.info(f"🗑️ Found {len(expired_movies)} expired movies to delete")
            for movie in expired_movies:
                movie_dict = row_to_dict(movie)
                movie_id = movie_dict['id']
                movie_title = movie_dict['title']
                logger.info(f"🗑️ Deleting expired movie: {movie_title} (ID: {movie_id})")
                if s3_client and movie_dict['video_key']:
                    try:
                        s3_client.delete_object(Bucket=BACKBLAZE_CONFIG['bucket'], Key=movie_dict['video_key'])
                        if movie_dict.get('poster_key'):
                            s3_client.delete_object(Bucket=BACKBLAZE_CONFIG['bucket'], Key=movie_dict['poster_key'])
                    except Exception as e:
                        logger.error(f"❌ Failed to delete from Backblaze B2: {str(e)}")
                cursor.execute('UPDATE movies SET is_active = 0 WHERE id = ?', (movie_id,))
                log_activity('system', 'system@bfcinema.com', 'auto_delete_movie', {
                    'movie_id': movie_id,
                    'movie_title': movie_title,
                    'deleted_at': now.isoformat()
                })
            conn.commit()
            deleted_count = len(expired_movies)
            logger.info(f"✅ Successfully deleted {deleted_count} expired movies")
        else:
            logger.info("✅ No expired movies found")
    except Exception as e:
        logger.error(f"❌ Error deleting expired movies: {str(e)}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    return deleted_count

def schedule_auto_deletion():
    try:
        schedule.every().day.at("02:00").do(delete_expired_movies)
        delete_expired_movies()
        logger.info("✅ Auto-deletion scheduler started")
        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(60)
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
    except Exception as e:
        logger.error(f"❌ Error starting auto-deletion scheduler: {str(e)}")

# =========== QR CODE FUNCTIONS ===========
def generate_receipt_qr(data):
    try:
        if QR_AVAILABLE:
            import segno
            import base64
            from io import BytesIO
            qrcode = segno.make(data, error='L')
            buffer = BytesIO()
            qrcode.save(buffer, kind='svg', scale=5)
            buffer.seek(0)
            svg_data = buffer.read().decode('utf-8')
            b64_str = base64.b64encode(svg_data.encode()).decode()
            return f"data:image/svg+xml;base64,{b64_str}"
        else:
            return generate_simple_qr(data)
    except Exception as e:
        logger.error(f"QR generation error: {str(e)}")
        return generate_simple_qr(data)

def generate_simple_qr(data):
    import base64
    svg_template = f'''<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
        <rect width="200" height="200" fill="#f8f9fa"/>
        <rect x="20" y="20" width="160" height="160" fill="white" stroke="#e50914" stroke-width="2"/>
        <text x="100" y="70" text-anchor="middle" font-family="Arial" font-size="16" fill="#333" font-weight="bold">B/F CINEMA</text>
        <text x="100" y="100" text-anchor="middle" font-family="Arial" font-size="12" fill="#666">RECEIPT</text>
        <text x="100" y="130" text-anchor="middle" font-family="Arial" font-size="10" fill="#999">{data[:30]}...</text>
        <text x="100" y="170" text-anchor="middle" font-family="Arial" font-size="8" fill="#aaa">Scan for verification</text>
    </svg>'''
    b64_str = base64.b64encode(svg_template.encode()).decode()
    return f"data:image/svg+xml;base64,{b64_str}"

# =========== ACCESS CONTROL FUNCTIONS ===========
def has_movie_access(user_id, movie_id):
    if not user_id:
        return False
    if user_id == 'admin_001':
        return True
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM user_access WHERE user_id = ? AND movie_id = ? AND is_active = 1 LIMIT 1', (user_id, movie_id))
        has_access = cursor.fetchone() is not None
        if not has_access:
            cursor.execute('SELECT free_preview FROM movies WHERE id = ?', (movie_id,))
            movie = cursor.fetchone()
            if movie and movie['free_preview']:
                has_access = True
        return has_access
    except Exception as e:
        logger.error(f"Access check error: {str(e)}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== CORS MIDDLEWARE ===========
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin', '')
    if origin in allowed_origins or '*':
        response.headers.add('Access-Control-Allow-Origin', origin)
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Range,X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS,PATCH')
    response.headers.add('Access-Control-Expose-Headers', 'Content-Range, Content-Length, Accept-Ranges')
    response.headers.add('Accept-Ranges', 'bytes')
    response.headers.add('Cache-Control', 'no-cache, no-store, must-revalidate')
    if RENDER:
        response.headers.add('X-Content-Type-Options', 'nosniff')
        response.headers.add('X-Frame-Options', 'SAMEORIGIN')
        response.headers.add('X-XSS-Protection', '1; mode=block')
    return response

@app.before_request
def before_request():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        origin = request.headers.get('Origin', '')
        if origin in allowed_origins or '*':
            response.headers.add('Access-Control-Allow-Origin', origin)
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Range,X-Requested-With')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS,PATCH')
        return response, 200

# =========== UPDATED: PAYMENT VERIFICATION ENDPOINT (No STK Push) ===========
@app.route('/api/movies/<int:movie_id>/verify-payment', methods=['POST'])
def verify_payment(movie_id):
    """Simple payment verification - user just confirms they paid via payment link"""
    conn = None
    cursor = None
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        data = request.get_json()
        
        # Simple confirmation - no complex MPesa parsing
        # User just confirms they completed payment via the payment link
        phone = data.get('phone', '').strip()
        confirm_payment = data.get('confirm_payment', False)
        
        if not confirm_payment:
            return jsonify({'success': False, 'error': 'Please confirm payment completion'}), 400
        
        # Get movie details
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM movies WHERE id = ?', (movie_id,))
        movie = cursor.fetchone()
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        movie_dict = row_to_dict(movie)
        
        # Check if user already has access
        if has_movie_access(session['user_id'], movie_id):
            return jsonify({'success': False, 'error': 'You already have access to this movie'}), 400
        
        # Generate simple transaction code
        transaction_code = f"LIP{datetime.now().strftime('%Y%m%d%H%M%S')}{session['user_id']}{movie_id}"
        
        # Create transaction record
        cursor.execute('''
            INSERT INTO transactions 
            (transaction_code, user_id, user_email, user_phone, movie_id, movie_title, amount, payment_date, payment_time, status, verified_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', CURRENT_TIMESTAMP)
        ''', (
            transaction_code,
            session['user_id'],
            session['email'],
            phone if phone else session.get('email', ''),
            movie_id,
            movie_dict['title'],
            movie_dict.get('price', 30.00),
            datetime.now().strftime('%d/%m/%y'),
            datetime.now().strftime('%I:%M %p'),
        ))
        
        transaction_id = cursor.lastrowid
        
        # Grant access to movie
        cursor.execute('''
            INSERT OR REPLACE INTO user_access (user_id, movie_id, transaction_id, is_active)
            VALUES (?, ?, ?, 1)
        ''', (session['user_id'], movie_id, transaction_id))
        
        # Add movie to downloads automatically
        video_url = generate_presigned_url(movie_dict['video_key'])
        poster_url = generate_presigned_url(movie_dict.get('poster_key'))
        
        movie_data = json.dumps({
            'id': movie_dict['id'],
            'title': movie_dict['title'],
            'description': movie_dict.get('description', ''),
            'poster': poster_url,
            'year': movie_dict.get('year'),
            'duration': movie_dict.get('duration'),
            'url': video_url,
            'views': movie_dict.get('views', 0),
            'downloads': movie_dict.get('download_count', 0)
        })
        
        cursor.execute('''
            INSERT OR REPLACE INTO downloads (user_id, movie_id, movie_data, downloaded_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ''', (session['user_id'], movie_id, movie_data))
        
        cursor.execute('UPDATE movies SET download_count = download_count + 1 WHERE id = ?', (movie_id,))
        cursor.execute('UPDATE users SET downloads = downloads + 1 WHERE id = ?', (session['user_id'],))
        
        conn.commit()
        
        # Generate receipt
        qr_code = generate_receipt_qr(f"""
        B/F Cinema Receipt
        Transaction: {transaction_code}
        User: {session['name']}
        Movie: {movie_dict['title']}
        Amount: KES {movie_dict.get('price', 30.00):.2f}
        Date: {datetime.now().strftime('%d/%m/%y')}
        Time: {datetime.now().strftime('%I:%M %p')}
        """)
        
        receipt = {
            'transaction_code': transaction_code,
            'user_name': session['name'],
            'user_email': session['email'],
            'user_phone': phone if phone else session.get('email', ''),
            'movie_title': movie_dict['title'],
            'amount': float(movie_dict.get('price', 30.00)),
            'date': datetime.now().strftime('%d/%m/%y'),
            'time': datetime.now().strftime('%I:%M %p'),
            'status': 'verified',
            'qr_code': qr_code,
            'receipt_id': f"BFR{transaction_id:06d}",
            'transaction_id': transaction_id,
            'movie_id': movie_id
        }
        
        log_activity(session['user_id'], session['email'], 'payment_successful_via_link', {
            'movie_id': movie_id,
            'transaction_code': transaction_code,
            'amount': float(movie_dict.get('price', 30.00)),
            'added_to_downloads': True
        })
        
        return jsonify({
            'success': True,
            'message': 'Payment confirmed successfully! Movie added to your downloads.',
            'receipt': receipt,
            'transaction_id': transaction_id,
            'movie_id': movie_id,
            'added_to_downloads': True
        })
        
    except Exception as e:
        logger.error(f"Payment verification error: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': f'Payment verification failed: {str(e)}'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== UPLOAD ENDPOINTS ===========
@app.route('/api/upload-file', methods=['POST'])
def upload_file():
    conn = None
    cursor = None
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        file_type = request.form.get('fileType', 'movie')
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        temp_dir = get_temp_dir()
        os.makedirs(temp_dir, exist_ok=True)
        
        unique_id = str(uuid.uuid4())[:8]
        extension = os.path.splitext(file.filename)[1] or ('.jpg' if file_type == 'poster' else '.mp4')
        filename = f"{unique_id}_{file_type}{extension}"
        filepath = os.path.join(temp_dir, filename)
        
        file.save(filepath)
        
        logger.info(f"✅ File uploaded: {filename} to {temp_dir}")
        
        return jsonify({
            'success': True,
            'filename': filename,
            'filepath': filepath,
            'file_type': file_type,
            'size': os.path.getsize(filepath)
        })
        
    except Exception as e:
        logger.error(f"File upload error: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/upload-movie-complete', methods=['POST'])
def upload_movie_complete():
    conn = None
    cursor = None
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        data = request.get_json()
        title = data.get('title', '').strip()
        description = data.get('description', '').strip()
        year = data.get('year')
        duration = data.get('duration')
        video_filename = data.get('video_filename')
        poster_filename = data.get('poster_filename')
        
        if not title:
            return jsonify({'success': False, 'error': 'Title is required'}), 400
        
        temp_dir = get_temp_dir()
        
        video_path = os.path.join(temp_dir, video_filename) if video_filename else None
        poster_path = os.path.join(temp_dir, poster_filename) if poster_filename else None
        
        if not video_path or not os.path.exists(video_path):
            return jsonify({'success': False, 'error': 'Video file not found'}), 400
        
        unique_id = str(uuid.uuid4())[:8]
        safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).strip().replace(' ', '_')
        
        video_ext = os.path.splitext(video_filename)[1].lower() or '.mp4'
        video_key = f"movies/{unique_id}_{safe_title}{video_ext}"
        
        video_url = None
        if s3_client:
            try:
                with open(video_path, 'rb') as f:
                    s3_client.upload_fileobj(f, BACKBLAZE_CONFIG['bucket'], video_key, ExtraArgs={'ContentType': 'video/mp4'})
                video_url = generate_presigned_url(video_key)
                logger.info(f"Video uploaded to Backblaze B2: {video_key}")
            except Exception as e:
                logger.error(f"Failed to upload to Backblaze B2: {str(e)}")
                video_url = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
        
        poster_key = None
        poster_url = None
        if poster_path and os.path.exists(poster_path):
            poster_ext = os.path.splitext(poster_filename)[1].lower() or '.jpg'
            poster_key = f"posters/{unique_id}_{safe_title}{poster_ext}"
            if s3_client:
                try:
                    with open(poster_path, 'rb') as f:
                        s3_client.upload_fileobj(f, BACKBLAZE_CONFIG['bucket'], poster_key, ExtraArgs={'ContentType': 'image/jpeg'})
                    poster_url = generate_presigned_url(poster_key)
                except Exception as e:
                    logger.error(f"Failed to upload poster to Backblaze B2: {str(e)}")
                    poster_url = "https://images.unsplash.com/photo-1536440136628-849c177e76a1?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&q=80"
        
        stream_url = f"/api/stream/{unique_id}"
        expiry_date = calculate_expiry_date()
        
        conn = get_db()
        cursor = conn.cursor()
        
        file_size = os.path.getsize(video_path)
        
        cursor.execute("""
            INSERT INTO movies (
                title, description, year, duration,
                video_key, poster_key,
                uploaded_by, uploaded_at, expires_at,
                views, download_count, storage,
                file_size, file_type, s3_url, stream_url, price
            ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, 0, 0, 'backblaze', ?, ?, ?, ?, ?)
        """, (
            title, description, year, duration, 
            video_key, poster_key, session.get('name', 'Admin'),
            expiry_date,
            file_size, 'video/mp4', video_url, stream_url, 30.00
        ))
        
        movie_id = cursor.lastrowid
        conn.commit()
        
        log_activity(session['user_id'], session['email'], 'upload_movie', {
            'title': title,
            'movie_id': movie_id,
            'video_url': video_url,
            'expires_at': expiry_date.isoformat()
        })
        
        try:
            if os.path.exists(video_path):
                os.remove(video_path)
            if poster_path and os.path.exists(poster_path):
                os.remove(poster_path)
        except:
            pass
        
        return jsonify({
            'success': True,
            'message': 'Movie uploaded successfully',
            'movie_id': movie_id,
            'title': title,
            'video_url': video_url,
            'stream_url': stream_url,
            'expires_at': expiry_date.isoformat(),
            'price': 30.00
        })
        
    except Exception as e:
        logger.error(f"Complete upload error: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Upload failed: ' + str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== VIDEO STREAMING ENDPOINTS ===========
@app.route('/api/stream-video/<int:movie_id>', methods=['GET'])
def stream_video_direct(movie_id):
    conn = None
    cursor = None
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        if not has_movie_access(session['user_id'], movie_id):
            return jsonify({'success': False, 'error': 'Access denied. Purchase required.'}), 403        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT video_key, title, s3_url, is_active FROM movies WHERE id = ?', (movie_id,))
        movie = cursor.fetchone()
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        movie_dict = row_to_dict(movie)
        
        if not movie_dict.get('is_active', 1):
            return jsonify({'success': False, 'error': 'This movie has expired and been removed from the system'}), 410
        
        video_url = None
        if movie_dict['video_key']:
            video_url = generate_presigned_url(movie_dict['video_key'])
        
        if not video_url and movie_dict['s3_url']:
            video_url = movie_dict['s3_url']
        elif not video_url:
            video_url = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
        
        return jsonify({
            'success': True,
            'video_url': video_url,
            'movie_title': movie_dict['title'],
            'content_type': 'video/mp4'
        })
        
    except Exception as e:
        logger.error(f"Stream video error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/stream/<movie_id>', methods=['GET'])
def stream_movie_proxy(movie_id):
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        try:
            movie_id_int = int(movie_id)
        except:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM movies WHERE video_key LIKE ?', (f'%{movie_id}%',))
            movie = cursor.fetchone()
            cursor.close()
            conn.close()
            if movie:
                movie_id_int = movie['id']
            else:
                return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        if not has_movie_access(session['user_id'], movie_id_int):
            return jsonify({'success': False, 'error': 'Access denied. Purchase required.'}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT video_key, file_type, is_active FROM movies WHERE id = ?', (movie_id_int,))
        movie = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not movie or not movie['video_key']:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        if not movie.get('is_active', 1):
            return jsonify({'success': False, 'error': 'This movie has expired and been removed from the system'}), 410
        
        video_url = generate_presigned_url(movie['video_key'])
        if not video_url:
            video_url = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
        
        range_header = request.headers.get('Range', None)
        
        if range_header:
            headers = {'Range': range_header}
            response = requests.get(video_url, headers=headers, stream=True)
            flask_response = Response(
                response.iter_content(chunk_size=8192),
                status=response.status_code,
                content_type=response.headers.get('content-type', 'video/mp4')
            )
            for key, value in response.headers.items():
                if key.lower() in ['content-range', 'content-length', 'accept-ranges', 'content-type']:
                    flask_response.headers[key] = value
            return flask_response
        else:
            return redirect(video_url, code=302)
            
    except Exception as e:
        logger.error(f"Stream proxy error: {str(e)}")
        return jsonify({'success': False, 'error': 'Streaming failed'}), 500

# =========== AUTHENTICATION ENDPOINTS ===========
@app.route('/api/login', methods=['POST'])
def login():
    conn = None
    cursor = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        logger.info(f"Login attempt for email: {email}")
        
        admin_email = 'BFCM2026@GMAIL.COM'
        admin_password = os.getenv('ADMIN_PASSWORD', 'ASGWG2@##...')
        
        if email.upper() == admin_email and password == admin_password:
            session.clear()
            session['user_id'] = 'admin_001'
            session['name'] = 'Administrator'
            session['email'] = admin_email
            session['is_admin'] = True
            session.permanent = True
            log_activity('admin_001', admin_email, 'admin_login')
            return jsonify({
                'success': True,
                'user': {
                    'id': 'admin_001',
                    'name': 'Administrator',
                    'email': admin_email,
                    'isAdmin': True,
                    'phone': '+254 700 505325'
                }
            })
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ? COLLATE NOCASE', (email,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user['id']))
            session.clear()
            session['user_id'] = user['id']
            session['name'] = user['name']
            session['email'] = user['email']
            session['is_admin'] = bool(user['is_admin'])
            session.permanent = True
            conn.commit()
            log_activity(user['id'], user['email'], 'user_login')
            return jsonify({
                'success': True,
                'user': {
                    'id': user['id'],
                    'name': user['name'],
                    'email': user['email'],
                    'phone': user['phone'],
                    'isAdmin': bool(user['is_admin'])
                }
            })
        
        return jsonify({'success': False, 'error': 'Invalid email or password'}), 401
        
    except Exception as e:
        logger.error(f"Login error: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/save-user', methods=['POST'])
def save_user():
    conn = None
    cursor = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        phone = data.get('phone', '').strip()
        password = data.get('password', '')
        
        if not name or not email or not password:
            return jsonify({'success': False, 'error': 'Name, email, and password are required'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = ? COLLATE NOCASE', (email,))
        if cursor.fetchone():
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        password_hash = generate_password_hash(password)
        cursor.execute('INSERT INTO users (name, email, phone, password_hash) VALUES (?, ?, ?, ?)', (name, email, phone, password_hash))
        user_id = cursor.lastrowid
        
        log_activity(user_id, email, 'user_registration', {'name': name})
        conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'Account created successfully',
            'user': {'id': user_id, 'name': name, 'email': email, 'phone': phone}
        })
        
    except Exception as e:
        logger.error(f"Registration error: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Registration failed'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        user_id = session.get('user_id')
        user_email = session.get('email')
        if user_id:
            log_activity(user_id, user_email, 'logout')
        session.clear()
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': 'Logout failed'}), 500

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    conn = None
    cursor = None
    try:
        if 'user_id' in session:
            user_id = session['user_id']
            if user_id == 'admin_001':
                return jsonify({
                    'authenticated': True,
                    'user': {
                        'id': 'admin_001',
                        'name': 'Administrator',
                        'email': 'BFCM2026@GMAIL.COM',
                        'isAdmin': True
                    }
                })
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            if user:
                return jsonify({
                    'authenticated': True,
                    'user': {
                        'id': user['id'],
                        'name': user['name'],
                        'email': user['email'],
                        'isAdmin': bool(user['is_admin'])
                    }
                })
        return jsonify({'authenticated': False})
    except Exception as e:
        logger.error(f"Auth check error: {str(e)}")
        return jsonify({'authenticated': False})
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== MOVIE ENDPOINTS ===========
@app.route('/api/movies', methods=['GET'])
def get_movies():
    conn = None
    cursor = None
    try:
        user_id = session.get('user_id')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM movies WHERE is_active=1 ORDER BY uploaded_at DESC")
        rows = cursor.fetchall()
        results = []
        for row in rows:
            movie = row_to_dict(row)
            video_url = generate_presigned_url(movie.get('video_key'))
            poster_url = generate_presigned_url(movie.get('poster_key'))
            if not video_url and movie.get('s3_url'):
                video_url = movie.get('s3_url')
            if not video_url:
                video_url = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
            if not poster_url:
                poster_url = "https://images.unsplash.com/photo-1536440136628-849c177e76a1?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&q=80"
            has_access = has_movie_access(user_id, movie['id'])
            stream_url = movie.get('stream_url')
            if not stream_url:
                stream_url = f"/api/stream-video/{movie['id']}"
            days_remaining = None
            if movie.get('expires_at'):
                expiry_date = datetime.fromisoformat(movie['expires_at'])
                days_remaining = (expiry_date - datetime.now()).days
            results.append({
                'id': movie['id'],
                'title': movie['title'],
                'description': movie.get('description', 'No description'),
                'year': movie.get('year'),
                'duration': movie.get('duration'),
                'url': video_url,
                'stream_url': stream_url,
                'poster': poster_url,
                'views': movie.get('views', 0),
                'downloads': movie.get('download_count', 0),
                'uploaded_at': movie.get('uploaded_at'),
                'expires_at': movie.get('expires_at'),
                'days_remaining': days_remaining,
                'has_access': has_access,
                'free_preview': bool(movie.get('free_preview', False)),
                'file_type': movie.get('file_type', 'video/mp4'),
                'file_size': movie.get('file_size', 0),
                'price': float(movie.get('price', 30.00))
            })
        return jsonify(success=True, movies=results)
    except Exception as e:
        logger.error(f"Get movies error: {traceback.format_exc()}")
        return jsonify(success=False, error="Failed to load movies"), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/movies/<int:movie_id>/watch', methods=['POST'])
def watch_movie(movie_id):
    conn = None
    cursor = None
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        if not has_movie_access(session['user_id'], movie_id):
            return jsonify({'success': False, 'error': 'Access denied. Purchase required.'}), 403
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT is_active FROM movies WHERE id = ?', (movie_id,))
        movie = cursor.fetchone()
        if not movie or not movie['is_active']:
            return jsonify({'success': False, 'error': 'This movie has expired and been removed from the system'}), 410
        cursor.execute('UPDATE movies SET views = views + 1 WHERE id = ?', (movie_id,))
        cursor.execute('INSERT INTO watch_history (user_id, movie_id, watched_at) VALUES (?, ?, ?)', (session['user_id'], movie_id, datetime.now()))
        conn.commit()
        log_activity(session['user_id'], session['email'], 'watch_movie', {'movie_id': movie_id})
        return jsonify({'success': True, 'message': 'View recorded'})
    except Exception as e:
        logger.error(f"Watch movie error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to record view'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== USER PROFILE ENDPOINTS ===========
@app.route('/api/user/downloads', methods=['GET'])
def get_user_downloads():
    conn = None
    cursor = None
    try:
        if 'user_id' not in session or session['user_id'] == 'admin_001':
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DISTINCT m.*, ua.access_granted_at as downloaded_at
            FROM movies m
            LEFT JOIN user_access ua ON m.id = ua.movie_id AND ua.user_id = ?
            WHERE ua.user_id = ? AND ua.is_active = 1 AND m.is_active = 1
            ORDER BY ua.access_granted_at DESC
        ''', (session['user_id'], session['user_id']))
        rows = cursor.fetchall()
        download_dict = {}
        for row in rows:
            movie = row_to_dict(row)
            movie_id = movie['id']
            if movie_id not in download_dict:
                video_url = generate_presigned_url(movie.get('video_key'))
                poster_url = generate_presigned_url(movie.get('poster_key'))
                days_remaining = None
                if movie.get('expires_at'):
                    expiry_date = datetime.fromisoformat(movie['expires_at'])
                    days_remaining = (expiry_date - datetime.now()).days
                download_dict[movie_id] = {
                    'movieId': movie_id,
                    'downloadedAt': movie.get('downloaded_at') or datetime.now().isoformat(),
                    'movieData': {
                        'id': movie_id,
                        'title': movie['title'],
                        'poster': poster_url,
                        'year': movie.get('year'),
                        'duration': movie.get('duration'),
                        'url': video_url,
                        'description': movie.get('description', ''),
                        'views': movie.get('views', 0),
                        'downloads': movie.get('download_count', 0),
                        'is_active': bool(movie.get('is_active', 1)),
                        'expires_at': movie.get('expires_at'),
                        'days_remaining': days_remaining,
                        'price': float(movie.get('price', 30.00))
                    }
                }
        download_list = list(download_dict.values())
        return jsonify({'success': True, 'downloads': download_list})
    except Exception as e:
        logger.error(f"Get downloads error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load downloads'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    conn = None
    cursor = None
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        if session['user_id'] == 'admin_001':
            user_data = {
                'id': 'admin_001',
                'name': 'Administrator',
                'email': 'BFCM2026@GMAIL.COM',
                'phone': '+254 700 505325',
                'createdAt': datetime.now().isoformat(),
                'moviesWatched': 0,
                'downloads': 0,
                'isAdmin': True
            }
        else:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
            user = cursor.fetchone()
            if not user:
                return jsonify({'success': False, 'error': 'User not found'}), 404
            user_dict = row_to_dict(user)
            user_data = {
                'id': user_dict['id'],
                'name': user_dict['name'],
                'email': user_dict['email'],
                'phone': user_dict['phone'],
                'createdAt': user_dict['created_at'],
                'moviesWatched': user_dict.get('movies_watched', 0),
                'downloads': user_dict.get('downloads', 0),
                'isAdmin': bool(user_dict.get('is_admin', False))
            }
        return jsonify({'success': True, 'user': user_data})
    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load profile'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/user/change-password', methods=['POST'])
def change_password():
    conn = None
    cursor = None
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_new_password = data.get('confirm_new_password')
        if not current_password or not new_password or not confirm_new_password:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        if new_password != confirm_new_password:
            return jsonify({'success': False, 'error': 'New passwords do not match'}), 400
        if len(new_password) < 6:
            return jsonify({'success': False, 'error': 'New password must be at least 6 characters'}), 400
        if session['user_id'] == 'admin_001':
            if current_password != os.getenv('ADMIN_PASSWORD', 'ASGWG2@##...'):
                return jsonify({'success': False, 'error': 'Current password is incorrect'}), 400
            return jsonify({'success': True, 'message': 'Admin password cannot be changed via web interface'})
        else:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash FROM users WHERE id = ?', (session['user_id'],))
            user = cursor.fetchone()
            if not user or not check_password_hash(user['password_hash'], current_password):
                return jsonify({'success': False, 'error': 'Current password is incorrect'}), 400
            new_password_hash = generate_password_hash(new_password)
            cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, session['user_id']))
            conn.commit()
        log_activity(session['user_id'], session['email'], 'change_password', {})
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    except Exception as e:
        logger.error(f"Change password error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to change password'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== ADMIN ENDPOINTS ===========
@app.route('/api/admin/stats', methods=['GET'])
def get_admin_stats():
    conn = None
    cursor = None
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM movies WHERE is_active = 1')
        total_movies = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM users')
        total_users = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM downloads')
        total_downloads = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM movies WHERE expires_at < ? AND is_active = 1', (datetime.now(),))
        expired_movies = cursor.fetchone()[0]
        cursor.execute('SELECT SUM(file_size) FROM movies WHERE is_active = 1')
        total_size = cursor.fetchone()[0] or 0
        storage_used_gb = round(total_size / (1024 * 1024 * 1024), 2)
        cursor.execute('SELECT SUM(amount) FROM transactions WHERE status = "verified"')
        total_revenue = cursor.fetchone()[0] or 0
        cursor.execute('SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 10')
        rows = cursor.fetchall()
        activity_list = []
        for row in rows:
            act = row_to_dict(row)
            try:
                details = json.loads(act['details']) if act['details'] else {}
            except:
                details = {}
            activity_list.append({
                'time': act['timestamp'],
                'action': act['action'],
                'user': act['user_email'],
                'details': details
            })
        return jsonify({
            'success': True,
            'stats': {
                'total_movies': total_movies,
                'total_users': total_users,
                'total_downloads': total_downloads,
                'expired_movies': expired_movies,
                'storage_used': storage_used_gb,
                'total_revenue': float(total_revenue),
                'recent_activity': activity_list
            }
        })
    except Exception as e:
        logger.error(f"Admin stats error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load stats'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/admin/movies', methods=['GET'])
def get_admin_movies():
    conn = None
    cursor = None
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM movies ORDER BY uploaded_at DESC')
        rows = cursor.fetchall()
        movie_list = []
        for row in rows:
            movie = row_to_dict(row)
            video_url = generate_presigned_url(movie.get('video_key'))
            poster_url = generate_presigned_url(movie.get('poster_key'))
            if not video_url and movie.get('s3_url'):
                video_url = movie.get('s3_url')
            days_remaining = None
            if movie.get('expires_at'):
                expiry_date = datetime.fromisoformat(movie['expires_at'])
                days_remaining = (expiry_date - datetime.now()).days
            movie_list.append({
                'id': movie['id'],
                'title': movie['title'],
                'description': movie.get('description', ''),
                'year': movie.get('year'),
                'duration': movie.get('duration'),
                'video_url': video_url,
                'poster_url': poster_url or "https://images.unsplash.com/photo-1536440136628-849c177e76a1?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&q=80",
                'views': movie.get('views', 0),
                'downloads': movie.get('download_count', 0),
                'uploaded_at': movie.get('uploaded_at'),
                'expires_at': movie.get('expires_at'),
                'days_remaining': days_remaining,
                'is_active': bool(movie.get('is_active', 1)),
                'file_size': movie.get('file_size', 0),
                'file_type': movie.get('file_type', 'video/mp4'),
                'free_preview': bool(movie.get('free_preview', False)),
                'stream_url': movie.get('stream_url', f"/api/stream-video/{movie['id']}"),
                'price': float(movie.get('price', 30.00))
            })
        return jsonify({'success': True, 'movies': movie_list})
    except Exception as e:
        logger.error(f"Get admin movies error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load movies'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/admin/users', methods=['GET'])
def get_admin_users():
    conn = None
    cursor = None
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, email, phone, created_at, downloads, movies_watched, last_login FROM users WHERE email != "BFCM2026@GMAIL.COM" ORDER BY created_at DESC')
        rows = cursor.fetchall()
        user_list = []
        for row in rows:
            user = row_to_dict(row)
            user_list.append({
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'phone': user['phone'],
                'joined': user['created_at'],
                'downloads': user.get('downloads', 0),
                'movies_watched': user.get('movies_watched', 0),
                'last_login': user['last_login']
            })
        return jsonify({'success': True, 'users': user_list})
    except Exception as e:
        logger.error(f"Get users error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load users'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/admin/movies/<int:movie_id>', methods=['DELETE'])
def delete_movie(movie_id):
    conn = None
    cursor = None
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM movies WHERE id = ?', (movie_id,))
        movie = cursor.fetchone()
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        movie_dict = row_to_dict(movie)
        if s3_client and movie_dict['video_key']:
            try:
                s3_client.delete_object(Bucket=BACKBLAZE_CONFIG['bucket'], Key=movie_dict['video_key'])
                if movie_dict.get('poster_key'):
                    s3_client.delete_object(Bucket=BACKBLAZE_CONFIG['bucket'], Key=movie_dict['poster_key'])
            except Exception as e:
                logger.warning(f"Failed to delete from Backblaze B2: {str(e)}")
        cursor.execute('DELETE FROM movies WHERE id = ?', (movie_id,))
        conn.commit()
        log_activity(session['user_id'], session['email'], 'delete_movie', {'movie_id': movie_id, 'title': movie_dict['title']})
        return jsonify({'success': True, 'message': 'Movie deleted successfully'})
    except Exception as e:
        logger.error(f"Delete movie error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to delete movie'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    conn = None
    cursor = None
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        if user_id == 1:
            return jsonify({'success': False, 'error': 'Cannot delete admin account'}), 400
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        user_dict = row_to_dict(user)
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        log_activity(session['user_id'], session['email'], 'delete_user', {'user_id': user_id, 'user_email': user_dict['email']})
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        logger.error(f"Delete user error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to delete user'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== HEALTH & STATIC ENDPOINTS ===========
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'service': 'B/F Cinema Streaming Platform',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected',
        'backblaze_connected': s3_client is not None,
        'version': '2.2.0',
        'render': RENDER
    })

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

# =========== ERROR HANDLERS ===========
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404

@app.errorhandler(410)
def gone(error):
    return jsonify({'success': False, 'error': 'This movie has expired and been removed from the system'}), 410

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

# =========== APPLICATION START ===========
if __name__ == '__main__':
    print("\n" + "="*60)
    print("🎬 B/F Cinema Streaming Platform - Version 2.2 (Payment Link Only)")
    print("="*60)
    print(f"📁 Environment: {'PRODUCTION' if RENDER else 'DEVELOPMENT'}")
    print(f"📁 Database: {get_db_path()}")
    print(f"📁 Database size: {os.path.getsize(get_db_path()) if os.path.exists(get_db_path()) else 0} bytes")
    print(f"☁️  Backblaze B2: {'✅ Connected' if s3_client else '❌ Not Connected'}")
    print(f"💰 Payment: ✅ Payment Link Only (No STK Push)")
    print(f"🔗 Payment URL: https://lipana.dev/pay/bf-cinema-movies")
    print(f"🗑️  Auto-deletion: ✅ Enabled (10 months expiry)")
    print("="*60)
    
    schedule_auto_deletion()
    print("✅ Auto-deletion scheduler started")
    
    print("\n🚀 Starting server...")
    
    if RENDER:
        print("🌐 Production server on Render")
    else:
        print("🌐 Development server available at:")
        print("   • http://localhost:5000")
        print("   • http://127.0.0.1:5000")
        print("\n📋 Login Credentials:")
        print("   Admin:")
        print("   • Email: BFCM2026@GMAIL.COM")
        print("   • Password: ASGWG2@##...")
    
    print("\n⚡ Press Ctrl+C to stop the server")
    print("="*60 + "\n")
    
    try:
        port = int(os.getenv('PORT', 5000))
        app.run(host='0.0.0.0', port=port, debug=not RENDER, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        print("\n👋 Server stopped")
    except Exception as e:
        print(f"\n❌ Error starting server: {str(e)}")
