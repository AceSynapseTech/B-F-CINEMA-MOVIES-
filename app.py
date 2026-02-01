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

# =========== CRITICAL FIX: IMPORTS ===========
# Try to import segno for QR codes, fallback if not available
try:
    import segno
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

# =========== CRITICAL FIX: DATABASE & STORAGE PATHS ===========
def get_persistent_path(filename):
    """Get persistent path that survives server restarts"""
    if os.getenv('RENDER', 'false').lower() == 'true':
        # On Render, use /data directory which is persistent
        data_dir = '/data'
        os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, filename)
    else:
        # Local development
        return filename

def get_db_path():
    """Get persistent database path - CRITICAL FIX"""
    return get_persistent_path('bfcinema.db')

def get_upload_dir():
    """Get persistent upload directory - CRITICAL FIX"""
    upload_dir = get_persistent_path('uploads')
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir

def get_temp_dir():
    """Get persistent temp directory - CRITICAL FIX"""
    temp_dir = get_persistent_path('temp_uploads')
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', static_url_path='')

# =========== RENDER-SPECIFIC CONFIGURATIONS ===========
RENDER = os.getenv('RENDER', 'false').lower() == 'true'

app.secret_key = os.getenv('SECRET_KEY', 'bfcinema_secret_key_2026_secure_12345_prod_change_me')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 31536000  # 1 year

app.config['MAX_CONTENT_LENGTH'] = 900 * 1024 * 1024  # 900MB

# Configure CORS
if RENDER:
    # Production settings
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
    # Development settings
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

# Configure CORS
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

# Initialize Backblaze B2 S3 client
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
    
    # Test connection
    response = s3_client.list_buckets()
    logger.info(f"✅ Connected to Backblaze B2. Buckets: {[b['Name'] for b in response['Buckets']]}")
    
except Exception as e:
    logger.error(f"❌ Failed to initialize Backblaze B2 S3 client: {str(e)}")

# =========== CRITICAL FIX: DATABASE INITIALIZATION ===========
def init_db():
    """Initialize database with all required tables - CRITICAL FIX"""
    try:
        db_path = get_db_path()
        logger.info(f"📂 Initializing persistent database at: {db_path}")
        logger.info(f"📁 Database file exists: {os.path.exists(db_path)}")
        logger.info(f"📁 Database file size: {os.path.getsize(db_path) if os.path.exists(db_path) else 0} bytes")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Enable foreign keys
        cursor.execute("PRAGMA foreign_keys = ON")
        
        # =========== CREATE CORE TABLES ===========
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
                stream_url TEXT
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
        
        # Transactions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_code TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                user_email TEXT NOT NULL,
                user_phone TEXT NOT NULL,
                movie_id INTEGER NOT NULL,
                movie_title TEXT NOT NULL,
                mpesa_message TEXT NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                payment_date TEXT,
                payment_time TEXT,
                status TEXT DEFAULT 'pending',
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
        logger.info(f"📁 Database location: {db_path}")
        logger.info(f"📁 Database size: {os.path.getsize(db_path)} bytes")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Database initialization error: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def get_db():
    """Get database connection - CRITICAL FIX"""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def row_to_dict(row):
    """Convert sqlite3.Row object to dictionary"""
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}

# =========== CRITICAL FIX: INITIALIZE ON STARTUP ===========
print("="*60)
print("🎬 B/F Cinema - Starting Database Initialization")
print("="*60)

# Create necessary directories
os.makedirs(get_upload_dir(), exist_ok=True)
os.makedirs(get_temp_dir(), exist_ok=True)

# Initialize database
if init_db():
    print("✅ Database initialized successfully")
else:
    print("❌ Database initialization failed")

print(f"📁 Database: {get_db_path()}")
print(f"📁 Uploads: {get_upload_dir()}")
print(f"📁 Temp: {get_temp_dir()}")
print(f"☁️  Backblaze B2: {'✅ Connected' if s3_client else '❌ Not Connected'}")
print("="*60)

# =========== BACKUP DATABASE FUNCTION ===========
def backup_database():
    """Create database backup"""
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

# Create initial backup
backup_database()

# =========== HELPER FUNCTIONS ===========
def generate_presigned_url(key, expires=7200):
    """Generate presigned URL with proper content type for videos"""
    if not s3_client or not key:
        logger.warning(f"S3 client not available or key empty: {key}")
        return None
    
    try:
        # Determine content type based on file extension
        content_type = 'video/mp4'  # default
        
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
        
        logger.info(f"Generating presigned URL for key: {key}, Content-Type: {content_type}")
        
        # Generate URL with proper headers for video streaming
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
        
        logger.info(f"Generated presigned URL: {url[:100]}...")
        return url
        
    except Exception as e:
        logger.error(f"❌ Presigned URL error for key {key}: {str(e)}")
        return None

def generate_s3_public_url(key):
    """Generate direct Backblaze B2 public URL"""
    if not key:
        return None
    
    endpoint = BACKBLAZE_CONFIG['endpoint']
    bucket = BACKBLAZE_CONFIG['bucket']
    
    if 'backblazeb2.com' in endpoint:
        import re
        match = re.search(r'https://s3\.(.+?)\.backblazeb2\.com', endpoint)
        if match:
            region = match.group(1)
            return f"https://{bucket}.s3.{region}.backblazeb2.com/{key}"
    
    return f"{endpoint}/file/{bucket}/{key}"

def log_activity(user_id, user_email, action, details=None):
    """Log user activity"""
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
    """Calculate expiry date 10 months from now"""
    return datetime.now() + timedelta(days=300)

def delete_expired_movies():
    """Delete movies that have passed their expiry date"""
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
            WHERE expires_at IS NOT NULL 
            AND expires_at < ? 
            AND is_active = 1
        ''', (now,))
        
        expired_movies = cursor.fetchall()
        
        if expired_movies:
            logger.info(f"🗑️ Found {len(expired_movies)} expired movies to delete")
            
            for movie in expired_movies:
                movie_dict = row_to_dict(movie)
                movie_id = movie_dict['id']
                movie_title = movie_dict['title']
                
                logger.info(f"🗑️ Deleting expired movie: {movie_title} (ID: {movie_id})")
                
                # Delete from Backblaze B2 if available
                if s3_client and movie_dict['video_key']:
                    try:
                        s3_client.delete_object(Bucket=BACKBLAZE_CONFIG['bucket'], Key=movie_dict['video_key'])
                        logger.info(f"✅ Deleted video from Backblaze B2: {movie_dict['video_key']}")
                        
                        if movie_dict.get('poster_key'):
                            s3_client.delete_object(Bucket=BACKBLAZE_CONFIG['bucket'], Key=movie_dict['poster_key'])
                            logger.info(f"✅ Deleted poster from Backblaze B2: {movie_dict['poster_key']}")
                            
                    except Exception as e:
                        logger.error(f"❌ Failed to delete from Backblaze B2 for movie {movie_id}: {str(e)}")
                
                # Mark movie as inactive in database
                cursor.execute('UPDATE movies SET is_active = 0 WHERE id = ?', (movie_id,))
                
                # Log the deletion
                log_activity('system', 'system@bfcinema.com', 'auto_delete_movie', {
                    'movie_id': movie_id,
                    'movie_title': movie_title,
                    'uploaded_at': movie_dict['uploaded_at'],
                    'expires_at': movie_dict['expires_at'],
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
    """Schedule automatic deletion of expired movies"""
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

# =========== MPESA FUNCTIONS ===========
def parse_mpesa_message(message):
    """Parse MPesa message to extract transaction details"""
    try:
        message = ' '.join(message.strip().split())
        
        # Exact pattern for MPesa confirmation message
        pattern = r'([A-Z0-9]{10})\s+Confirmed\.\s+Ksh?([\d,]+\.\d{2})\s+(?:paid\s+to|sent\s+to)\s+PETER\s+KINUTHIA\s+NGIGI\.\s+on\s+(\d{1,2}/\d{1,2}/\d{2})\s+at\s+(\d{1,2}:\d{2}\s+[AP]M)\.'
        
        match = re.search(pattern, message, re.IGNORECASE)
        
        if match:
            return {
                'transaction_code': match.group(1).upper(),
                'amount': float(match.group(2).replace(',', '')),
                'recipient': "PETER KINUTHIA NGIGI",
                'date': match.group(3),
                'time': match.group(4),
                'is_valid': True,
                'raw_message': message
            }
        
        # Alternative pattern
        pattern2 = r'([A-Z0-9]{10})\s+Confirmed\.\s+Ksh?([\d,]+\.\d{2})\s+(?:paid\s+to|sent\s+to)\s+PETER\s+KINUTHIA\s+NGIGI\.'
        match2 = re.search(pattern2, message, re.IGNORECASE)
        
        if match2:
            date_pattern = r'on\s+(\d{1,2}/\d{1,2}/\d{2})\s+at\s+(\d{1,2}:\d{2}\s+[AP]M)'
            date_match = re.search(date_pattern, message, re.IGNORECASE)
            
            if date_match:
                return {
                    'transaction_code': match2.group(1).upper(),
                    'amount': float(match2.group(2).replace(',', '')),
                    'recipient': "PETER KINUTHIA NGIGI",
                    'date': date_match.group(1),
                    'time': date_match.group(2),
                    'is_valid': True,
                    'raw_message': message
                }
            else:
                return {
                    'transaction_code': match2.group(1).upper(),
                    'amount': float(match2.group(2).replace(',', '')),
                    'recipient': "PETER KINUTHIA NGIGI",
                    'date': None,
                    'time': None,
                    'is_valid': True,
                    'raw_message': message
                }
        
        # Check for valid transaction code and amount
        fallback_pattern = r'([A-Z0-9]{10}).*?Ksh?([\d,]+\.\d{2})'
        fallback_match = re.search(fallback_pattern, message, re.IGNORECASE)
        
        if fallback_match:
            if "PETER KINUTHIA NGIGI".lower() in message.lower():
                return {
                    'transaction_code': fallback_match.group(1).upper(),
                    'amount': float(fallback_match.group(2).replace(',', '')),
                    'recipient': "PETER KINUTHIA NGIGI",
                    'date': None,
                    'time': None,
                    'is_valid': True,
                    'raw_message': message
                }
        
        return {'is_valid': False, 'error': 'Invalid MPesa message format'}
    
    except Exception as e:
        logger.error(f"MPesa parse error: {str(e)}")
        return {'is_valid': False, 'error': f'Error parsing message: {str(e)}'}

def generate_receipt_qr(data):
    """Generate QR code"""
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
    """Generate simple SVG without QR code"""
    import base64
    
    svg_template = f'''<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
        <rect width="200" height="200" fill="#f8f9fa"/>
        <rect x="20" y="20" width="160" height="160" fill="white" stroke="#e50914" stroke-width="2"/>
        <text x="100" y="70" text-anchor="middle" font-family="Arial" font-size="16" fill="#333" font-weight="bold">
            B/F CINEMA
        </text>
        <text x="100" y="100" text-anchor="middle" font-family="Arial" font-size="12" fill="#666">
            RECEIPT
        </text>
        <text x="100" y="130" text-anchor="middle" font-family="Arial" font-size="10" fill="#999">
            {data[:30]}...
        </text>
        <text x="100" y="170" text-anchor="middle" font-family="Arial" font-size="8" fill="#aaa">
            Scan for verification
        </text>
    </svg>'''
    
    b64_str = base64.b64encode(svg_template.encode()).decode()
    return f"data:image/svg+xml;base64,{b64_str}"

def check_transaction_code_unique(transaction_code):
    """Check if transaction code is unique"""
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM transactions WHERE transaction_code = ?', (transaction_code,))
        exists = cursor.fetchone() is not None
        return not exists
    except Exception as e:
        logger.error(f"Check transaction error: {str(e)}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== ACCESS CONTROL FUNCTIONS ===========
def has_movie_access(user_id, movie_id):
    """Check if user has permanent access to a movie"""
    if not user_id:
        return False
    
    if user_id == 'admin_001':
        return True
    
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 1 FROM user_access 
            WHERE user_id = ? AND movie_id = ? AND is_active = 1
            LIMIT 1
        ''', (user_id, movie_id))
        
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
    """Add CORS headers to all responses"""
    origin = request.headers.get('Origin', '')
    if origin in allowed_origins or '*':
        response.headers.add('Access-Control-Allow-Origin', origin)
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Range,X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS,PATCH')
    response.headers.add('Access-Control-Expose-Headers', 'Content-Range, Content-Length, Accept-Ranges')
    
    response.headers.add('Accept-Ranges', 'bytes')
    response.headers.add('Cache-Control', 'no-cache, no-store, must-revalidate')
    response.headers.add('Pragma', 'no-cache')
    response.headers.add('Expires', '0')
    
    if RENDER:
        response.headers.add('X-Content-Type-Options', 'nosniff')
        response.headers.add('X-Frame-Options', 'SAMEORIGIN')
        response.headers.add('X-XSS-Protection', '1; mode=block')
    
    return response

@app.before_request
def before_request():
    """Handle CORS preflight requests"""
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        origin = request.headers.get('Origin', '')
        if origin in allowed_origins or '*':
            response.headers.add('Access-Control-Allow-Origin', origin)
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Range,X-Requested-With')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS,PATCH')
        return response, 200
    
    if RENDER and request.path.startswith('/api/'):
        logger.info(f"{request.method} {request.path} - {request.remote_addr}")

# =========== UPLOAD ENDPOINTS ===========
@app.route('/api/upload-file', methods=['POST'])
def upload_file():
    """Simple file upload endpoint"""
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
        
        # Save to persistent temp directory
        temp_dir = get_temp_dir()
        os.makedirs(temp_dir, exist_ok=True)
        
        # Generate unique filename
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
    """Complete movie upload after all files are uploaded"""
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
        
        # Upload to Backblaze B2
        unique_id = str(uuid.uuid4())[:8]
        safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).strip().replace(' ', '_')
        
        # Upload video
        video_ext = os.path.splitext(video_filename)[1].lower() or '.mp4'
        video_key = f"movies/{unique_id}_{safe_title}{video_ext}"
        
        video_url = None
        if s3_client:
            try:
                with open(video_path, 'rb') as f:
                    s3_client.upload_fileobj(
                        f,
                        BACKBLAZE_CONFIG['bucket'],
                        video_key,
                        ExtraArgs={'ContentType': 'video/mp4'}
                    )
                video_url = generate_presigned_url(video_key)
                logger.info(f"Video uploaded to Backblaze B2: {video_key}")
            except Exception as e:
                logger.error(f"Failed to upload to Backblaze B2: {str(e)}")
                video_url = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
        
        # Upload poster if exists
        poster_key = None
        poster_url = None
        if poster_path and os.path.exists(poster_path):
            poster_ext = os.path.splitext(poster_filename)[1].lower() or '.jpg'
            poster_key = f"posters/{unique_id}_{safe_title}{poster_ext}"
            
            if s3_client:
                try:
                    with open(poster_path, 'rb') as f:
                        s3_client.upload_fileobj(
                            f,
                            BACKBLAZE_CONFIG['bucket'],
                            poster_key,
                            ExtraArgs={'ContentType': 'image/jpeg'}
                        )
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
                file_size, file_type, s3_url, stream_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, 0, 0, 'backblaze', ?, ?, ?, ?)
        """, (
            title, description, year, duration, 
            video_key, poster_key, session.get('name', 'Admin'),
            expiry_date,
            file_size, 'video/mp4', video_url, stream_url
        ))
        
        movie_id = cursor.lastrowid
        conn.commit()
        
        log_activity(session['user_id'], session['email'], 'upload_movie', {
            'title': title,
            'movie_id': movie_id,
            'video_url': video_url,
            'expires_at': expiry_date.isoformat()
        })
        
        # Cleanup temp files
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
            'expires_at': expiry_date.isoformat()
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
    """Get streaming URL for a movie"""
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
    """Proxy stream for movie"""
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

@app.route('/api/movies/<int:movie_id>/stream-url', methods=['GET'])
def get_movie_stream_url(movie_id):
    """Get streaming URL for movie with access check"""
    conn = None
    cursor = None
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        if not has_movie_access(session['user_id'], movie_id):
            return jsonify({'success': False, 'error': 'Access denied. Purchase required.'}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT video_key, file_type, title, s3_url, is_active FROM movies WHERE id = ?', (movie_id,))
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
        
        if not video_url:
            video_url = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
        
        stream_url = f"/api/stream/{movie_id}"
        
        return jsonify({
            'success': True,
            'stream_url': stream_url,
            'direct_url': video_url,
            'content_type': movie_dict['file_type'] or 'video/mp4',
            'movie_title': movie_dict['title']
        })
        
    except Exception as e:
        logger.error(f"Stream URL error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/simple-stream/<int:movie_id>', methods=['GET'])
def simple_stream_movie(movie_id):
    """Simple streaming endpoint"""
    conn = None
    cursor = None
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        if not has_movie_access(session['user_id'], movie_id):
            return jsonify({'success': False, 'error': 'Access denied. Purchase required.'}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT video_key, file_type, title, s3_url, is_active FROM movies WHERE id = ?', (movie_id,))
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
        
        if not video_url:
            video_url = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
        
        stream_url = f"/api/stream/{movie_id}"
        
        return jsonify({
            'success': True,
            'stream_url': stream_url,
            'direct_url': video_url,
            'content_type': movie_dict['file_type'] or 'video/mp4',
            'movie_title': movie_dict['title'],
            'can_watch': True
        })
        
    except Exception as e:
        logger.error(f"Simple stream error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== DEBUG ENDPOINTS ===========
@app.route('/api/debug/movie/<int:movie_id>', methods=['GET'])
def debug_movie(movie_id):
    """Debug endpoint to check movie URLs"""
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM movies WHERE id = ?', (movie_id,))
        movie = cursor.fetchone()
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'})
        
        movie_dict = row_to_dict(movie)
        
        video_url = generate_presigned_url(movie_dict['video_key'])
        poster_url = generate_presigned_url(movie_dict['poster_key'])
        
        video_accessible = False
        if video_url:
            try:
                head_response = requests.head(video_url, timeout=5)
                video_accessible = head_response.status_code == 200
            except:
                video_accessible = False
        
        days_remaining = None
        if movie_dict.get('expires_at'):
            expiry_date = datetime.fromisoformat(movie_dict['expires_at'])
            days_remaining = (expiry_date - datetime.now()).days
        
        return jsonify({
            'success': True,
            'movie': {
                'id': movie_dict['id'],
                'title': movie_dict['title'],
                'video_key': movie_dict['video_key'],
                'video_url': video_url,
                'video_accessible': video_accessible,
                'poster_url': poster_url,
                's3_url': movie_dict.get('s3_url'),
                'stream_url': movie_dict.get('stream_url'),
                'file_size': movie_dict.get('file_size', 0),
                'file_type': movie_dict.get('file_type', 'video/mp4'),
                'free_preview': bool(movie_dict.get('free_preview', False)),
                'is_active': bool(movie_dict.get('is_active', 1)),
                'uploaded_at': movie_dict.get('uploaded_at'),
                'expires_at': movie_dict.get('expires_at'),
                'days_remaining': days_remaining
            },
            'backblaze_connected': s3_client is not None
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/test-video', methods=['GET'])
def test_video():
    """Test video endpoint"""
    test_url = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
    return jsonify({
        'success': True,
        'test_url': test_url,
        'message': 'Test video from Google'
    })

@app.route('/api/test-video-playback/<int:movie_id>', methods=['GET'])
def test_video_playback(movie_id):
    """Test video playback for a specific movie"""
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT video_key, title, s3_url, is_active FROM movies WHERE id = ?', (movie_id,))
        movie = cursor.fetchone()
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'})
        
        movie_dict = row_to_dict(movie)
        
        video_url = generate_presigned_url(movie_dict['video_key'])
        if not video_url and movie_dict['s3_url']:
            video_url = movie_dict['s3_url']
        
        return jsonify({
            'success': True,
            'title': movie_dict['title'],
            'video_key': movie_dict['video_key'],
            'video_url': video_url,
            'is_active': bool(movie_dict.get('is_active', 1)),
            'html_test': f'''
            <html>
            <body style="background: black; color: white; padding: 20px;">
                <h1>Video Test: {movie_dict['title']}</h1>
                <p>Testing video playback for movie ID: {movie_id}</p>
                <p>Video Key: {movie_dict['video_key']}</p>
                <p>Video URL: <a href="{video_url}" target="_blank">{video_url}</a></p>
                <p>Status: {"✅ Active" if movie_dict.get('is_active', 1) else "❌ Expired/Deleted"}</p>
                <div style="margin: 20px 0;">
                    <h3>Video Player Test:</h3>
                    <video controls style="width: 80%; max-width: 800px;" autoplay>
                        <source src="{video_url}" type="video/mp4">
                        Your browser does not support the video tag.
                    </video>
                </div>
                <div style="margin: 20px 0;">
                    <h3>Direct Link:</h3>
                    <a href="{video_url}" style="color: #e50914;" target="_blank">Open video in new tab</a>
                </div>
            </body>
            </html>
            '''
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== HEALTH & CONNECTION ENDPOINTS ===========
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'B/F Cinema Streaming Platform',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected',
        'backblaze_connected': s3_client is not None,
        'version': '2.0.0',
        'render': RENDER,
        'environment': 'production' if RENDER else 'development'
    })

@app.route('/test-connection', methods=['GET'])
def test_backblaze_connection():
    """Test Backblaze B2 connection"""
    try:
        if s3_client:
            response = s3_client.list_buckets()
            buckets = [bucket['Name'] for bucket in response['Buckets']]
            bucket_exists = BACKBLAZE_CONFIG['bucket'] in buckets
            
            return jsonify({
                'success': True,
                'message': 'Backblaze B2 connection successful',
                'bucket_exists': bucket_exists,
                'buckets': buckets
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Backblaze B2 client not initialized',
                'bucket_exists': False
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Connection failed: {str(e)}',
            'bucket_exists': False
        })

# =========== NEW: SYSTEM CHECK ENDPOINT ===========
@app.route('/api/debug/system-check', methods=['GET'])
def system_check():
    """Check if everything is working"""
    try:
        db_path = get_db_path()
        upload_dir = get_upload_dir()
        temp_dir = get_temp_dir()
        
        checks = {
            'database_exists': os.path.exists(db_path),
            'database_size': os.path.getsize(db_path) if os.path.exists(db_path) else 0,
            'upload_dir_exists': os.path.exists(upload_dir),
            'temp_dir_exists': os.path.exists(temp_dir),
            'backblaze_connected': s3_client is not None,
            'render_environment': RENDER,
            'timestamp': datetime.now().isoformat(),
            'database_path': db_path,
            'upload_dir_path': upload_dir,
            'temp_dir_path': temp_dir
        }
        
        # Check if we can write to database
        if os.path.exists(db_path):
            try:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) as count FROM sqlite_master')
                result = cursor.fetchone()
                checks['database_writable'] = True
                checks['table_count'] = result['count']
                
                # Check each table
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                table_info = []
                for table in tables:
                    table_name = table['name']
                    cursor.execute(f"SELECT COUNT(*) as count FROM {table_name}")
                    count = cursor.fetchone()['count']
                    table_info.append({
                        'table': table_name,
                        'row_count': count
                    })
                checks['tables'] = table_info
                
                cursor.close()
                conn.close()
            except Exception as e:
                checks['database_writable'] = False
                checks['database_error'] = str(e)
        
        return jsonify({'success': True, 'checks': checks})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# =========== AUTHENTICATION ENDPOINTS ===========
@app.route('/api/login', methods=['POST'])
def login():
    """User login endpoint"""
    conn = None
    cursor = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        logger.info(f"Login attempt for email: {email}")
        
        # Admin login
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
        
        # Regular user login
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
    """User registration endpoint"""
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
        
        # Validation
        if not name or not email or not password:
            return jsonify({'success': False, 'error': 'Name, email, and password are required'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if user already exists
        cursor.execute('SELECT * FROM users WHERE email = ? COLLATE NOCASE', (email,))
        if cursor.fetchone():
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        # Create user
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (name, email, phone, password_hash)
            VALUES (?, ?, ?, ?)
        ''', (name, email, phone, password_hash))
        
        user_id = cursor.lastrowid
        
        log_activity(user_id, email, 'user_registration', {'name': name})
        
        conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'Account created successfully',
            'user': {
                'id': user_id,
                'name': name,
                'email': email,
                'phone': phone
            }
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
    """Logout endpoint"""
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
    """Check if user is authenticated"""
    conn = None
    cursor = None
    try:
        if 'user_id' in session:
            user_id = session['user_id']
            
            # Admin user
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
            
            # Regular user
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
    """Get all movies"""
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
                'file_size': movie.get('file_size', 0)
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
    """Record movie watch"""
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
        
        cursor.execute('''
            INSERT INTO watch_history (user_id, movie_id, watched_at)
            VALUES (?, ?, ?)
        ''', (session['user_id'], movie_id, datetime.now()))
        
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

@app.route('/api/movies/<int:movie_id>/download', methods=['POST'])
def download_movie(movie_id):
    """Record movie download"""
    conn = None
    cursor = None
    try:
        if 'user_id' not in session or session['user_id'] == 'admin_001':
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        if not has_movie_access(session['user_id'], movie_id):
            return jsonify({'success': False, 'error': 'Access denied. Purchase required.'}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT is_active FROM movies WHERE id = ?', (movie_id,))
        movie = cursor.fetchone()
        
        if not movie or not movie['is_active']:
            return jsonify({'success': False, 'error': 'This movie has expired and been removed from the system'}), 410
        
        cursor.execute('SELECT * FROM movies WHERE id = ?', (movie_id,))
        movie = cursor.fetchone()
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        movie_dict = row_to_dict(movie)
        
        cursor.execute('UPDATE movies SET download_count = download_count + 1 WHERE id = ?', (movie_id,))
        cursor.execute('UPDATE users SET downloads = downloads + 1 WHERE id = ?', (session['user_id'],))
        
        video_url = generate_presigned_url(movie_dict['video_key'])
        poster_url = generate_presigned_url(movie_dict.get('poster_key'))
        
        movie_data = json.dumps({
            'id': movie_dict['id'],
            'title': movie_dict['title'],
            'description': movie_dict.get('description', ''),
            'poster': poster_url,
            'year': movie_dict.get('year'),
            'url': video_url,
            'views': movie_dict.get('views', 0),
            'downloads': movie_dict.get('download_count', 0)
        })
        
        cursor.execute('''
            INSERT INTO downloads (user_id, movie_id, movie_data)
            VALUES (?, ?, ?)
        ''', (session['user_id'], movie_id, movie_data))
        
        conn.commit()
        
        log_activity(session['user_id'], session['email'], 'download_movie', {
            'movie_id': movie_id,
            'title': movie_dict['title']
        })
        
        return jsonify({'success': True, 'message': 'Download recorded'})
        
    except Exception as e:
        logger.error(f"Download movie error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to record download'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/movies/<int:movie_id>', methods=['GET'])
def get_movie_details(movie_id):
    """Get movie details"""
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM movies WHERE id=?", (movie_id,))
        movie = cursor.fetchone()

        if not movie:
            return jsonify(success=False, error="Movie not found"), 404
        
        movie_dict = row_to_dict(movie)

        video_url = generate_presigned_url(movie_dict['video_key'])
        poster_url = generate_presigned_url(movie_dict.get('poster_key'))
        
        if not video_url and movie_dict.get('s3_url'):
            video_url = movie_dict['s3_url']
        
        user_id = session.get('user_id')
        has_access = has_movie_access(user_id, movie_id)
        
        days_remaining = None
        if movie_dict.get('expires_at'):
            expiry_date = datetime.fromisoformat(movie_dict['expires_at'])
            days_remaining = (expiry_date - datetime.now()).days
        
        return jsonify(success=True, movie={
            'id': movie_dict['id'],
            'title': movie_dict['title'],
            'description': movie_dict.get('description', ''),
            'year': movie_dict.get('year'),
            'duration': movie_dict.get('duration'),
            'url': video_url,
            'stream_url': f"/api/stream-video/{movie_dict['id']}",
            'poster': poster_url,
            'views': movie_dict.get('views', 0),
            'downloads': movie_dict.get('download_count', 0),
            'free_preview': bool(movie_dict.get('free_preview', False)),
            'is_active': bool(movie_dict.get('is_active', 1)),
            'uploaded_at': movie_dict.get('uploaded_at'),
            'expires_at': movie_dict.get('expires_at'),
            'days_remaining': days_remaining,
            'has_access': has_access
        })
    except Exception as e:
        logger.error(f"Get movie details error: {str(e)}")
        return jsonify(success=False, error="Failed to load movie"), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== PAYMENT ENDPOINTS ===========
@app.route('/api/movies/<int:movie_id>/verify-payment', methods=['POST'])
def verify_payment(movie_id):
    """Verify MPesa payment and grant access to movie"""
    conn = None
    cursor = None
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        data = request.get_json()
        phone = data.get('phone', '').strip()
        transaction_code = data.get('transaction_code', '').strip().upper()
        mpesa_message = data.get('mpesa_message', '').strip()
        
        # Validate input
        if not phone or not transaction_code or not mpesa_message:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        if not re.match(r'^254[17]\d{8}$', phone):
            return jsonify({'success': False, 'error': 'Invalid phone number format. Use format: 2547XXXXXXXX'}), 400
        
        if not re.match(r'^[A-Z0-9]{10}$', transaction_code):
            return jsonify({'success': False, 'error': 'Transaction code must be 10 alphanumeric characters'}), 400
        
        # Parse MPesa message
        parsed = parse_mpesa_message(mpesa_message)
        
        if not parsed['is_valid']:
            return jsonify({'success': False, 'error': parsed.get('error', 'Invalid MPesa message')}), 400
        
        if parsed['transaction_code'] != transaction_code:
            return jsonify({'success': False, 'error': f'Transaction code mismatch. Message has: {parsed["transaction_code"]}, you entered: {transaction_code}'}), 400
        
        amount = parsed['amount']
        if abs(amount - 30.00) > 0.01:
            return jsonify({'success': False, 'error': f'Amount must be KES 30.00. Received: KES {amount:.2f}'}), 400
        
        if parsed['recipient'].upper() != "PETER KINUTHIA NGIGI":
            return jsonify({'success': False, 'error': f'Payment must be sent to PETER KINUTHIA NGIGI. Received: {parsed["recipient"]}'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM transactions WHERE transaction_code = ?', (transaction_code,))
        existing = cursor.fetchone()
        
        if existing:
            return jsonify({'success': False, 'error': 'This transaction code has already been used'}), 400
        
        cursor.execute('SELECT * FROM movies WHERE id = ?', (movie_id,))
        movie = cursor.fetchone()
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        movie_dict = row_to_dict(movie)
        
        cursor.execute('''
            INSERT INTO transactions 
            (transaction_code, user_id, user_email, user_phone, movie_id, movie_title, 
             mpesa_message, amount, payment_date, payment_time, status, verified_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', CURRENT_TIMESTAMP)
        ''', (
            transaction_code,
            session['user_id'],
            session['email'],
            phone,
            movie_id,
            movie_dict['title'],
            mpesa_message,
            amount,
            parsed.get('date', datetime.now().strftime('%d/%m/%y')),
            parsed.get('time', datetime.now().strftime('%I:%M %p')),
        ))
        
        transaction_id = cursor.lastrowid
        
        cursor.execute('''
            INSERT OR REPLACE INTO user_access (user_id, movie_id, transaction_id, is_active)
            VALUES (?, ?, ?, 1)
        ''', (session['user_id'], movie_id, transaction_id))
        
        # ADD MOVIE TO DOWNLOADS AUTOMATICALLY
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
        
        # Get receipt data
        cursor.execute('''
            SELECT t.*, u.name as user_name, u.email
            FROM transactions t
            JOIN users u ON t.user_id = u.id
            WHERE t.id = ?
        ''', (transaction_id,))
        
        transaction = cursor.fetchone()
        transaction_dict = row_to_dict(transaction)
        
        qr_code = generate_receipt_qr(f"""
        B/F Cinema Receipt
        Transaction: {transaction_code}
        User: {transaction_dict['user_name']}
        Movie: {movie_dict['title']}
        Amount: KES {amount:.2f}
        Date: {parsed.get('date', 'N/A')}
        Time: {parsed.get('time', 'N/A')}
        """)
        
        receipt = {
            'transaction_code': transaction_code,
            'user_name': transaction_dict['user_name'],
            'user_email': transaction_dict['email'],
            'user_phone': phone,
            'movie_title': movie_dict['title'],
            'amount': amount,
            'date': parsed.get('date', datetime.now().strftime('%d/%m/%y')),
            'time': parsed.get('time', datetime.now().strftime('%I:%M %p')),
            'status': 'verified',
            'qr_code': qr_code,
            'receipt_id': f"BFR{transaction_id:06d}",
            'transaction_id': transaction_id,
            'movie_id': movie_id
        }
        
        log_activity(session['user_id'], session['email'], 'payment_verified', {
            'movie_id': movie_id,
            'transaction_code': transaction_code,
            'amount': amount,
            'added_to_downloads': True
        })
        
        return jsonify({
            'success': True,
            'message': 'Payment verified successfully! Movie added to your downloads.',
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

@app.route('/api/transactions/<int:transaction_id>/receipt', methods=['GET'])
def get_receipt(transaction_id):
    """Generate receipt for transaction"""
    conn = None
    cursor = None
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT t.*, u.name as user_name, u.email, u.phone
            FROM transactions t
            JOIN users u ON t.user_id = u.id
            WHERE t.id = ? AND (t.user_id = ? OR ? = 1)
        ''', (transaction_id, session['user_id'], session.get('is_admin', False)))
        
        transaction = cursor.fetchone()
        
        if not transaction:
            return jsonify({'success': False, 'error': 'Transaction not found'}), 404
        
        transaction_dict = row_to_dict(transaction)
        
        qr_data = f"""
        B/F Cinema Receipt
        Transaction: {transaction_dict['transaction_code']}
        User: {transaction_dict['user_name']}
        Movie: {transaction_dict['movie_title']}
        Amount: KES {transaction_dict['amount']}
        Date: {transaction_dict['payment_date']} {transaction_dict['payment_time']}
        Status: {transaction_dict['status']}
        """
        
        qr_code = generate_receipt_qr(qr_data)
        
        receipt = {
            'transaction_code': transaction_dict['transaction_code'],
            'user_name': transaction_dict['user_name'],
            'user_email': transaction_dict['email'],
            'user_phone': transaction_dict['user_phone'],
            'movie_title': transaction_dict['movie_title'],
            'amount': transaction_dict['amount'],
            'date': transaction_dict['payment_date'],
            'time': transaction_dict['payment_time'],
            'status': transaction_dict['status'],
            'qr_code': qr_code,
            'receipt_id': f"BFR{transaction_id:06d}"
        }
        
        return jsonify({'success': True, 'receipt': receipt})
        
    except Exception as e:
        logger.error(f"Receipt generation error: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Failed to generate receipt'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/transactions/<int:transaction_id>/download-receipt', methods=['GET'])
def download_receipt_file(transaction_id):
    """Download receipt as PDF/text file"""
    conn = None
    cursor = None
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT t.*, u.name as user_name, u.email, m.title as movie_title
            FROM transactions t
            JOIN users u ON t.user_id = u.id
            JOIN movies m ON t.movie_id = m.id
            WHERE t.id = ? AND (t.user_id = ? OR ? = 1)
        ''', (transaction_id, session['user_id'], session.get('is_admin', False)))
        
        transaction = cursor.fetchone()
        
        if not transaction:
            return jsonify({'success': False, 'error': 'Transaction not found'}), 404
        
        transaction_dict = row_to_dict(transaction)
        
        receipt_text = f"""
B/F CINEMA - OFFICIAL RECEIPT
{'='*50}
Receipt ID: BFR{transaction_dict['id']:06d}
Transaction Code: {transaction_dict['transaction_code']}
Date: {transaction_dict['payment_date'] or datetime.now().strftime('%d/%m/%y')}
Time: {transaction_dict['payment_time'] or datetime.now().strftime('%I:%M %p')}
Status: {transaction_dict['status'].upper()}

CUSTOMER DETAILS
{'-'*50}
Name: {transaction_dict['user_name']}
Email: {transaction_dict['email']}
Phone: {transaction_dict['user_phone']}

MOVIE PURCHASED
{'-'*50}
Movie: {transaction_dict['movie_title']}
Amount: KES {transaction_dict['amount']:.2f}

TRANSACTION DETAILS
{'-'*50}
Payment Method: MPesa Till (7048202)
Business Name: PETER KINUTHIA NGIGI
Verified: {transaction_dict['verified_at'] or 'Immediately'}

{'='*50}
This is an official receipt from B/F Cinema.
For support: bfCinemamovies@gmail.com
Phone: +254 700 505325

Thank you for your purchase!
        """
        
        from io import BytesIO
        
        output = BytesIO()
        output.write(receipt_text.encode('utf-8'))
        output.seek(0)
        
        return send_file(
            output,
            as_attachment=True,
            download_name=f"BFCinema_Receipt_{transaction_dict['transaction_code']}.txt",
            mimetype='text/plain'
        )
        
    except Exception as e:
        logger.error(f"Download receipt error: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Failed to download receipt'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/movies/<int:movie_id>/check-access', methods=['GET'])
def check_movie_access(movie_id):
    """Check if user has access to movie"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'has_access': False, 'error': 'Authentication required'}), 401
        
        has_access = has_movie_access(session['user_id'], movie_id)
        
        return jsonify({
            'success': True, 
            'has_access': has_access, 
            'is_admin': session.get('is_admin', False)
        })
        
    except Exception as e:
        logger.error(f"Access check error: {str(e)}")
        return jsonify({'success': False, 'has_access': False, 'error': 'Access check failed'}), 500

# =========== ADMIN FINANCE ENDPOINTS ===========
@app.route('/api/admin/transactions', methods=['GET'])
def get_all_transactions():
    """Get all transactions for admin"""
    conn = None
    cursor = None
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT t.*, u.name as user_name, u.email, u.phone
            FROM transactions t
            JOIN users u ON t.user_id = u.id
            ORDER BY t.created_at DESC
        ''')
        
        rows = cursor.fetchall()
        
        cursor.execute('SELECT COUNT(*) as total, SUM(amount) as revenue FROM transactions WHERE status = "verified"')
        stats = cursor.fetchone()
        
        cursor.execute('SELECT COUNT(*) as fraud FROM transactions WHERE status = "fraudulent"')
        fraud_stats = cursor.fetchone()
        
        transaction_list = []
        for row in rows:
            trans = row_to_dict(row)
            transaction_list.append({
                'id': trans['id'],
                'transaction_code': trans['transaction_code'],
                'user_name': trans['user_name'],
                'user_email': trans['email'],
                'user_phone': trans['phone'],
                'movie_title': trans['movie_title'],
                'amount': trans['amount'],
                'payment_date': trans['payment_date'],
                'payment_time': trans['payment_time'],
                'status': trans['status'],
                'created_at': trans['created_at'],
                'mpesa_message': trans['mpesa_message']
            })
        
        stats_dict = row_to_dict(stats)
        fraud_dict = row_to_dict(fraud_stats)
        
        return jsonify({
            'success': True,
            'transactions': transaction_list,
            'stats': {
                'total': stats_dict['total'] or 0,
                'revenue': float(stats_dict['revenue'] or 0),
                'fraudulent': fraud_dict['fraud'] or 0,
                'verified': stats_dict['total'] or 0
            }
        })
        
    except Exception as e:
        logger.error(f"Get transactions error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load transactions'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/admin/transactions/<int:transaction_id>/mark-fraudulent', methods=['POST'])
def mark_transaction_fraudulent(transaction_id):
    """Mark transaction as fraudulent and terminate user"""
    conn = None
    cursor = None
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        data = request.get_json()
        reason = data.get('reason', '')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM transactions WHERE id = ?', (transaction_id,))
        transaction = cursor.fetchone()
        
        if not transaction:
            return jsonify({'success': False, 'error': 'Transaction not found'}), 404
        
        transaction_dict = row_to_dict(transaction)
        
        cursor.execute('''
            UPDATE transactions 
            SET status = 'fraudulent' 
            WHERE id = ?
        ''', (transaction_id,))
        
        cursor.execute('''
            DELETE FROM user_access 
            WHERE transaction_id = ?
        ''', (transaction_id,))
        
        cursor.execute('DELETE FROM users WHERE id = ?', (transaction_dict['user_id'],))
        
        conn.commit()
        
        log_activity(session['user_id'], session['email'], 'transaction_marked_fraudulent', {
            'transaction_id': transaction_id,
            'user_id': transaction_dict['user_id'],
            'reason': reason
        })
        
        return jsonify({'success': True, 'message': 'User terminated and access revoked'})
        
    except Exception as e:
        logger.error(f"Mark fraudulent error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to mark as fraudulent'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== ADMIN ENDPOINTS ===========
@app.route('/api/admin/stats', methods=['GET'])
def get_admin_stats():
    """Get admin statistics"""
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
        
        cursor.execute('''
            SELECT * FROM activity_log 
            ORDER BY timestamp DESC 
            LIMIT 10
        ''')
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

@app.route('/api/admin/upload-movie', methods=['POST'])
def upload_movie():
    """Upload movie to Backblaze B2"""
    conn = None
    cursor = None
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        year = request.form.get('year')
        duration = request.form.get('duration')
        free_preview = request.form.get('free_preview', 'false') == 'true'
        
        poster_file = request.files.get('poster')
        video_file = request.files.get('movie')
        
        if not title:
            return jsonify({'success': False, 'error': 'Title is required'}), 400
        
        if not video_file:
            return jsonify({'success': False, 'error': 'Movie file is required'}), 400
        
        logger.info(f"Starting upload for: {title}")
        
        video_size = len(video_file.read())
        video_file.seek(0)
        
        uploaded_by = session.get('name', 'Admin')
        
        if s3_client:
            try:
                unique_id = str(uuid.uuid4())[:8]
                safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).strip().replace(' ', '_')
                
                video_ext = os.path.splitext(video_file.filename)[1].lower()
                if video_ext == '':
                    video_ext = '.mp4'
                
                file_type = 'video/mp4' if video_ext == '.mp4' else f'video/{video_ext[1:]}'
                
                video_key = f"movies/{unique_id}_{safe_title}{video_ext}"
                logger.info(f"Uploading video to Backblaze B2: {video_key}")
                
                s3_client.upload_fileobj(
                    video_file,
                    BACKBLAZE_CONFIG['bucket'],
                    video_key,
                    ExtraArgs={'ContentType': file_type}
                )
                
                video_url = generate_presigned_url(video_key)
                
                poster_key = None
                poster_url = None
                
                if poster_file and poster_file.filename:
                    poster_ext = os.path.splitext(poster_file.filename)[1].lower()
                    if poster_ext == '':
                        poster_ext = '.jpg'
                    
                    poster_key = f"posters/{unique_id}_{safe_title}{poster_ext}"
                    logger.info(f"Uploading poster to Backblaze B2: {poster_key}")
                    
                    s3_client.upload_fileobj(
                        poster_file,
                        BACKBLAZE_CONFIG['bucket'],
                        poster_key,
                        ExtraArgs={'ContentType': 'image/jpeg'}
                    )
                    
                    poster_url = generate_presigned_url(poster_key)
                else:
                    poster_key = f"posters/default_{unique_id}.jpg"
                    poster_url = "https://images.unsplash.com/photo-1536440136628-849c177e76a1?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&q=80"
                
                stream_url = f"/api/stream/{unique_id}"
                expiry_date = calculate_expiry_date()
                
                conn = get_db()
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO movies (
                        title, description, year, duration,
                        video_key, poster_key,
                        uploaded_by, uploaded_at, expires_at,
                        views, download_count, storage,
                        file_size, file_type, free_preview, s3_url, stream_url
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, 0, 0, 'backblaze', ?, ?, ?, ?, ?)
                """, (
                    title, description, year, duration, 
                    video_key, poster_key, uploaded_by,
                    expiry_date,
                    video_size, file_type, free_preview, video_url, stream_url
                ))
                
                movie_id = cursor.lastrowid
                
                conn.commit()
                
                log_activity(session['user_id'], session['email'], 'upload_movie', {
                    'title': title,
                    'movie_id': movie_id,
                    'video_key': video_key,
                    'poster_key': poster_key,
                    'video_url': video_url,
                    'expires_at': expiry_date.isoformat()
                })
                
                return jsonify({
                    'success': True,
                    'message': 'Movie uploaded successfully to Backblaze B2',
                    'movie': {
                        'id': movie_id,
                        'title': title,
                        'video_key': video_key,
                        'poster_key': poster_key,
                        'video_url': video_url,
                        'stream_url': stream_url,
                        'free_preview': free_preview,
                        'expires_at': expiry_date.isoformat()
                    }
                })
                
            except Exception as e:
                logger.error(f"Backblaze B2 upload error: {traceback.format_exc()}")
                return jsonify({'success': False, 'error': f'Backblaze B2 upload failed: {str(e)}'}), 500
        else:
            logger.warning("Backblaze B2 client not available, using fallback URLs")
            
            video_key = f"fallback_movies/{title.replace(' ', '_')}.mp4"
            poster_key = f"fallback_posters/{title.replace(' ', '_')}.jpg"
            
            video_url = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
            poster_url = "https://images.unsplash.com/photo-1536440136628-849c177e76a1?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&q=80"
            stream_url = f"/api/stream/{title.replace(' ', '_')}"
            
            expiry_date = calculate_expiry_date()
            
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO movies (
                    title, description, year, duration,
                    video_key, poster_key,
                    uploaded_by, uploaded_at, expires_at,
                    views, download_count, storage,
                    file_size, file_type, free_preview, s3_url, stream_url
                ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, 0, 0, 'backblaze', ?, ?, ?, ?, ?)
            """, (
                title, description, year, duration, 
                video_key, poster_key, uploaded_by,
                expiry_date,
                video_size, 'video/mp4', free_preview, video_url, stream_url
            ))
            
            movie_id = cursor.lastrowid
            
            conn.commit()
            
            log_activity(session['user_id'], session['email'], 'upload_movie', {
                'title': title,
                'movie_id': movie_id,
                'note': 'Backblaze B2 not available, used fallback URLs',
                'expires_at': expiry_date.isoformat()
            })
            
            return jsonify({
                'success': True,
                'message': 'Movie saved with fallback URLs (Backblaze B2 not available)',
                'movie': {
                    'id': movie_id,
                    'title': title,
                    'video_key': video_key,
                    'poster_key': poster_key,
                    'video_url': video_url,
                    'stream_url': stream_url,
                    'free_preview': free_preview,
                    'expires_at': expiry_date.isoformat()
                }
            })
        
    except Exception as e:
        logger.error(f"Upload movie error: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Upload failed: ' + str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/admin/movies/<int:movie_id>', methods=['DELETE'])
def delete_movie(movie_id):
    """Delete movie from Backblaze B2 and database"""
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
        
        log_activity(session['user_id'], session['email'], 'delete_movie', {
            'movie_id': movie_id,
            'title': movie_dict['title']
        })
        
        return jsonify({'success': True, 'message': 'Movie deleted successfully'})
        
    except Exception as e:
        logger.error(f"Delete movie error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to delete movie'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/api/admin/movies', methods=['GET'])
def get_admin_movies():
    """Get all movies for admin"""
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
                's3_url': movie.get('s3_url', ''),
                'video_key': movie.get('video_key', ''),
                'poster_key': movie.get('poster_key', '')
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

@app.route('/api/admin/delete-expired-movies', methods=['POST'])
def manual_delete_expired_movies():
    """Manually trigger deletion of expired movies (Admin only)"""
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        deleted_count = delete_expired_movies()
        
        return jsonify({
            'success': True,
            'message': f'Deleted {deleted_count} expired movies',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        logger.error(f"Manual delete expired movies error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to delete expired movies'}), 500

@app.route('/api/admin/users', methods=['GET'])
def get_admin_users():
    """Get all users for admin"""
    conn = None
    cursor = None
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, name, email, phone, created_at, downloads, movies_watched, last_login
            FROM users 
            WHERE email != 'BFCM2026@GMAIL.COM'
            ORDER BY created_at DESC
        ''')
        
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

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete user"""
    conn = None
    cursor = None
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        if user_id == 1:  # Prevent deleting admin
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
        
        log_activity(session['user_id'], session['email'], 'delete_user', {
            'user_id': user_id,
            'user_email': user_dict['email']
        })
        
        return jsonify({'success': True, 'message': 'User deleted successfully'})
        
    except Exception as e:
        logger.error(f"Delete user error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to delete user'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== USER PROFILE ENDPOINTS ===========
@app.route('/api/user/downloads', methods=['GET'])
def get_user_downloads():
    """Get user's downloads - includes both downloaded and purchased movies"""
    conn = None
    cursor = None
    try:
        if 'user_id' not in session or session['user_id'] == 'admin_001':
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Get movies user has purchased/accessed
        cursor.execute('''
            SELECT DISTINCT m.*, ua.access_granted_at as downloaded_at
            FROM movies m
            LEFT JOIN user_access ua ON m.id = ua.movie_id AND ua.user_id = ?
            WHERE ua.user_id = ? AND ua.is_active = 1 AND m.is_active = 1
            ORDER BY ua.access_granted_at DESC
        ''', (session['user_id'], session['user_id']))
        
        rows = cursor.fetchall()
        
        # Also get explicit downloads from downloads table
        cursor.execute('''
            SELECT d.*, m.title, m.poster_key, m.year, m.duration, m.video_key, m.is_active
            FROM downloads d
            JOIN movies m ON d.movie_id = m.id
            WHERE d.user_id = ? AND m.is_active = 1
            ORDER BY d.downloaded_at DESC
        ''', (session['user_id'],))
        
        explicit_downloads = cursor.fetchall()
        
        # Combine both lists (unique by movie_id)
        download_dict = {}
        
        # Add movies from user_access (purchased movies)
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
                        'days_remaining': days_remaining
                    }
                }
        
        # Add explicit downloads
        for row in explicit_downloads:
            download = row_to_dict(row)
            movie_id = download['movie_id']
            if movie_id not in download_dict:
                try:
                    movie_data = json.loads(download['movie_data']) if download.get('movie_data') else {}
                except:
                    movie_data = {}
                
                if 'url' not in movie_data:
                    video_url = generate_presigned_url(download.get('video_key'))
                    poster_url = generate_presigned_url(download.get('poster_key'))
                    
                    days_remaining = None
                    if download.get('expires_at'):
                        expiry_date = datetime.fromisoformat(download['expires_at'])
                        days_remaining = (expiry_date - datetime.now()).days
                    
                    download_dict[movie_id] = {
                        'movieId': movie_id,
                        'downloadedAt': download['downloaded_at'],
                        'movieData': {
                            'title': download['title'],
                            'poster': poster_url,
                            'year': download.get('year'),
                            'duration': download.get('duration'),
                            'url': video_url,
                            'is_active': bool(download.get('is_active', 1)),
                            'expires_at': download.get('expires_at'),
                            'days_remaining': days_remaining,
                            **movie_data
                        }
                    }
                else:
                    download_dict[movie_id] = {
                        'movieId': movie_id,
                        'downloadedAt': download['downloaded_at'],
                        'movieData': movie_data
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
    """Get user profile"""
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
    """Change user password"""
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

# =========== STATIC FILE SERVING ===========
@app.route('/')
def index():
    """Serve the main HTML file"""
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
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

@app.errorhandler(413)
def too_large(error):
    return jsonify({'success': False, 'error': 'File too large. Maximum size is 900MB'}), 413

# =========== DATABASE SCHEMA CHECK ===========
@app.route('/api/debug/db-schema', methods=['GET'])
def debug_db_schema():
    """Debug endpoint to check database schema"""
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(movies)")
        columns = cursor.fetchall()
        
        schema = []
        for col in columns:
            schema.append({
                'id': col[0],
                'name': col[1],
                'type': col[2],
                'notnull': col[3],
                'default': col[4],
                'pk': col[5]
            })
        
        column_names = [col['name'] for col in schema]
        
        return jsonify({
            'success': True,
            'table': 'movies',
            'columns': schema,
            'has_expires_at': 'expires_at' in column_names,
            'has_s3_url': 's3_url' in column_names,
            'has_stream_url': 'stream_url' in column_names,
            'message': 'Database schema check'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# =========== APPLICATION START ===========
if __name__ == '__main__':
    print("\n" + "="*60)
    print("🎬 B/F Cinema Streaming Platform - Version 2.0 (FIXED)")
    print("="*60)
    print(f"📁 Environment: {'PRODUCTION' if RENDER else 'DEVELOPMENT'}")
    print(f"📁 Database: {get_db_path()}")
    print(f"📁 Database exists: {os.path.exists(get_db_path())}")
    print(f"📁 Database size: {os.path.getsize(get_db_path()) if os.path.exists(get_db_path()) else 0} bytes")
    print(f"📁 Uploads: {get_upload_dir()}")
    print(f"📁 Temp: {get_temp_dir()}")
    print(f"☁️  Backblaze B2: {'✅ Connected' if s3_client else '❌ Not Connected'}")
    print(f"🔗 B2 Bucket: {BACKBLAZE_CONFIG['bucket']}")
    print(f"📍 Endpoint: {BACKBLAZE_CONFIG['endpoint']}")
    print(f"🗑️  Auto-deletion: ✅ Enabled (10 months expiry)")
    print("="*60)
    
    # Start the auto-deletion scheduler
    try:
        schedule_auto_deletion()
        print("✅ Auto-deletion scheduler started")
    except Exception as e:
        print(f"⚠️  Could not start auto-deletion scheduler: {str(e)}")
    
    print("\n🚀 Starting server...")
    
    if RENDER:
        print("🌐 Production server on Render")
        print("📋 Login Credentials:")
        print("   Admin:")
        print(f"   • Email: BFCM2026@GMAIL.COM")
        print("   • Password: [Set in Render environment variables]")
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
        
        app.run(
            host='0.0.0.0',
            port=port,
            debug=not RENDER,
            threaded=True,
            use_reloader=False
        )
    except KeyboardInterrupt:
        print("\n👋 Server stopped")
    except Exception as e:
        print(f"\n❌ Error starting server: {str(e)}")
