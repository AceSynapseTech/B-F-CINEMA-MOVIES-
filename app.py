from flask import Flask, request, jsonify, session, send_from_directory, redirect, send_file, Response, render_template
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
from io import BytesIO
import time
import re
import base64
import requests
import qrcode
from PIL import Image
import io
import sys

# =========== CONFIGURATION ===========
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, 
           static_folder='static',
           template_folder='templates',
           static_url_path='')

# =========== ENVIRONMENT CONFIG ===========
# Detect platform
IS_RENDER = os.getenv('RENDER', 'false').lower() == 'true'
IS_HEROKU = 'DYNO' in os.environ
IS_RAILWAY = 'RAILWAY_ENVIRONMENT' in os.environ
IS_PRODUCTION = IS_RENDER or IS_HEROKU or IS_RAILWAY

# App configuration
app.secret_key = os.getenv('SECRET_KEY', 'bf-cinema-multi-platform-2026-secure-key-change-in-production')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB

# Session configuration
app.config.update(
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax' if IS_PRODUCTION else None,
)

# =========== CORS CONFIGURATION ===========
# Allowed origins for multi-platform support
ALLOWED_ORIGINS = [
    'http://localhost:5000',
    'http://127.0.0.1:5000',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5173',  # Vite
    'http://127.0.0.1:5173',
    'http://localhost:8080',  # Vue/Capacitor
    'http://127.0.0.1:8080',
    'capacitor://localhost',
    'http://localhost',
    'https://localhost',
    'file://',  # For Electron
    'electron://*',  # For Electron apps
]

# Add deployment URLs
DEPLOYMENT_URL = os.getenv('DEPLOYMENT_URL')
if DEPLOYMENT_URL:
    ALLOWED_ORIGINS.append(DEPLOYMENT_URL)

RENDER_EXTERNAL_URL = os.getenv('RENDER_EXTERNAL_URL')
if RENDER_EXTERNAL_URL:
    ALLOWED_ORIGINS.append(RENDER_EXTERNAL_URL)
    ALLOWED_ORIGINS.append(RENDER_EXTERNAL_URL.replace('https://', 'http://'))

# Configure CORS
CORS(app, 
     origins=ALLOWED_ORIGINS,
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization', 'Accept', 'Range', 'X-Requested-With', 'Origin', 'X-Platform'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'HEAD'],
     expose_headers=['Content-Range', 'Content-Length', 'Accept-Ranges', 'X-Platform-Info'],
     max_age=86400)

# =========== WASABI S3 CONFIGURATION ===========
WASABI_CONFIG = {
    'access_key': os.getenv('WASABI_ACCESS_KEY', 'NLXDDRMUWSYD2PW7IY8S'),
    'secret_key': os.getenv('WASABI_SECRET_KEY', 'iFnXOuPM01lqjVJ4IaWLLsGdTrUqwoJc56S742rm'),
    'bucket': os.getenv('WASABI_BUCKET', 'bfcinema'),
    'region': os.getenv('WASABI_REGION', 'eu-central-2'),
    'endpoint': os.getenv('WASABI_ENDPOINT', 'https://s3.eu-central-2.wasabisys.com'),
    'public_url': f"https://{os.getenv('WASABI_BUCKET', 'bfcinema')}.s3.{os.getenv('WASABI_REGION', 'eu-central-2')}.wasabisys.com"
}

# Initialize S3 client
s3_client = None
try:
    s3_client = boto3.client(
        's3',
        endpoint_url=WASABI_CONFIG['endpoint'],
        aws_access_key_id=WASABI_CONFIG['access_key'],
        aws_secret_access_key=WASABI_CONFIG['secret_key'],
        region_name=WASABI_CONFIG['region'],
        config=boto3.session.Config(
            signature_version='s3v4',
            s3={'addressing_style': 'virtual'}
        )
    )
    # Test connection
    s3_client.list_buckets()
    logger.info("✅ Wasabi S3 client initialized successfully")
    S3_ENABLED = True
except Exception as e:
    logger.error(f"❌ Failed to initialize S3 client: {str(e)}")
    S3_ENABLED = False
    s3_client = None

# =========== DATABASE SETUP ===========
def get_db_path():
    """Get database path based on environment"""
    if IS_RENDER:
        return '/tmp/bfcinema.db'
    elif IS_HEROKU:
        return '/tmp/bfcinema.db'
    elif IS_RAILWAY:
        return '/tmp/bfcinema.db'
    else:
        return 'bfcinema.db'

def init_database():
    """Initialize database with all required tables"""
    db_path = get_db_path()
    logger.info(f"📦 Initializing database at: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Enable foreign keys and WAL mode for better concurrency
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.execute("PRAGMA synchronous = NORMAL")
        
        # =========== CORE TABLES ===========
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT,
                password_hash TEXT NOT NULL,
                avatar_url TEXT,
                is_admin BOOLEAN DEFAULT 0,
                is_active BOOLEAN DEFAULT 1,
                email_verified BOOLEAN DEFAULT 0,
                phone_verified BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                total_watch_time INTEGER DEFAULT 0,
                total_spent DECIMAL(10,2) DEFAULT 0.00,
                device_info TEXT,
                platform TEXT DEFAULT 'web'
            )
        ''')
        
        # Movies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS movies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                year INTEGER,
                genre TEXT,
                duration TEXT,
                director TEXT,
                cast TEXT,
                rating DECIMAL(3,1) DEFAULT 0.0,
                price DECIMAL(10,2) DEFAULT 30.00,
                video_url TEXT NOT NULL,
                video_key TEXT,
                poster_url TEXT,
                poster_key TEXT,
                trailer_url TEXT,
                file_size INTEGER,
                duration_seconds INTEGER,
                resolution TEXT DEFAULT '1080p',
                language TEXT DEFAULT 'English',
                subtitles TEXT DEFAULT '[]',
                is_featured BOOLEAN DEFAULT 0,
                is_trending BOOLEAN DEFAULT 0,
                is_free BOOLEAN DEFAULT 0,
                age_rating TEXT DEFAULT 'PG-13',
                views INTEGER DEFAULT 0,
                downloads INTEGER DEFAULT 0,
                likes INTEGER DEFAULT 0,
                uploader_id INTEGER,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (uploader_id) REFERENCES users(id) ON DELETE SET NULL
            )
        ''')
        
        # Transactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                movie_id INTEGER NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                currency TEXT DEFAULT 'KES',
                payment_method TEXT DEFAULT 'mpesa',
                phone_number TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                mpesa_code TEXT,
                receipt_number TEXT,
                payment_date TIMESTAMP,
                verified_at TIMESTAMP,
                verified_by INTEGER,
                notes TEXT,
                metadata TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE,
                FOREIGN KEY (verified_by) REFERENCES users(id) ON DELETE SET NULL
            )
        ''')
        
        # User access table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                movie_id INTEGER NOT NULL,
                transaction_id INTEGER,
                access_type TEXT DEFAULT 'purchase',
                access_granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                last_watched TIMESTAMP,
                watch_count INTEGER DEFAULT 0,
                progress_seconds INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE,
                FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE SET NULL,
                UNIQUE(user_id, movie_id)
            )
        ''')
        
        # Watch history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS watch_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                movie_id INTEGER NOT NULL,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP,
                duration_seconds INTEGER DEFAULT 0,
                progress_seconds INTEGER DEFAULT 0,
                percentage_complete INTEGER DEFAULT 0,
                device_info TEXT,
                platform TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE
            )
        ''')
        
        # Downloads table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                movie_id INTEGER NOT NULL,
                downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                file_path TEXT,
                file_size INTEGER,
                download_status TEXT DEFAULT 'completed',
                device_info TEXT,
                platform TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE
            )
        ''')
        
        # Favorites table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS favorites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                movie_id INTEGER NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE,
                UNIQUE(user_id, movie_id)
            )
        ''')
        
        # Reviews table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                movie_id INTEGER NOT NULL,
                rating INTEGER CHECK(rating >= 1 AND rating <= 5),
                comment TEXT,
                is_verified_purchase BOOLEAN DEFAULT 0,
                likes INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE,
                UNIQUE(user_id, movie_id)
            )
        ''')
        
        # Notifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                type TEXT DEFAULT 'info',
                is_read BOOLEAN DEFAULT 0,
                action_url TEXT,
                metadata TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                language TEXT DEFAULT 'en',
                theme TEXT DEFAULT 'dark',
                video_quality TEXT DEFAULT 'auto',
                autoplay BOOLEAN DEFAULT 1,
                notifications_email BOOLEAN DEFAULT 1,
                notifications_push BOOLEAN DEFAULT 1,
                parental_controls TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_movies_active ON movies(is_active, uploaded_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_movies_featured ON movies(is_featured, is_active)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_access_active ON user_access(user_id, is_active)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id, created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_watch_history_user ON watch_history(user_id, started_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_favorites_user ON favorites(user_id, added_at)')
        
        # Check if admin exists
        admin_email = 'BFCM2026@GMAIL.COM'
        cursor.execute('SELECT id FROM users WHERE email = ?', (admin_email,))
        admin_exists = cursor.fetchone()
        
        if not admin_exists:
            admin_password = os.getenv('ADMIN_PASSWORD', 'Admin@2026')
            password_hash = generate_password_hash(admin_password)
            cursor.execute('''
                INSERT INTO users (name, email, phone, password_hash, is_admin, is_active, email_verified)
                VALUES (?, ?, ?, ?, 1, 1, 1)
            ''', ('System Administrator', admin_email, '+254700505325', password_hash))
            logger.info("👑 Admin user created")
        
        conn.commit()
        conn.close()
        
        logger.info("✅ Database initialized successfully with all tables")
        
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {str(e)}")
        logger.error(traceback.format_exc())
        raise

# Initialize database on startup
init_database()

# =========== DATABASE HELPER FUNCTIONS ===========
def get_db_connection():
    """Get database connection with row factory"""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn

def dict_from_row(row):
    """Convert SQLite row to dictionary"""
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}

def execute_query(query, params=(), fetchone=False, fetchall=False):
    """Execute SQL query safely"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        if fetchone:
            result = cursor.fetchone()
            result = dict_from_row(result) if result else None
        elif fetchall:
            result = [dict_from_row(row) for row in cursor.fetchall()]
        else:
            result = cursor.lastrowid
        
        if not query.strip().upper().startswith('SELECT'):
            conn.commit()
        
        return result
    except Exception as e:
        conn.rollback()
        logger.error(f"Query error: {str(e)}")
        raise
    finally:
        conn.close()

# =========== S3 HELPER FUNCTIONS ===========
def upload_to_s3(file_data, key, content_type='application/octet-stream', is_public=False):
    """Upload file to Wasabi S3"""
    if not S3_ENABLED:
        logger.warning("S3 not enabled, skipping upload")
        return None
    
    try:
        extra_args = {
            'ContentType': content_type,
            'ACL': 'public-read' if is_public else 'private'
        }
        
        if isinstance(file_data, bytes):
            s3_client.put_object(
                Bucket=WASABI_CONFIG['bucket'],
                Key=key,
                Body=file_data,
                **extra_args
            )
        else:
            # Assume it's a file path
            s3_client.upload_file(
                file_data,
                WASABI_CONFIG['bucket'],
                key,
                ExtraArgs=extra_args
            )
        
        # Generate URL
        if is_public:
            url = f"{WASABI_CONFIG['public_url']}/{key}"
        else:
            url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': WASABI_CONFIG['bucket'], 'Key': key},
                ExpiresIn=3600 * 24 * 7  # 7 days
            )
        
        logger.info(f"✅ Uploaded to S3: {key}")
        return url
        
    except Exception as e:
        logger.error(f"❌ S3 upload failed: {str(e)}")
        return None

def delete_from_s3(key):
    """Delete file from S3"""
    if not S3_ENABLED:
        return False
    
    try:
        s3_client.delete_object(Bucket=WASABI_CONFIG['bucket'], Key=key)
        logger.info(f"🗑️  Deleted from S3: {key}")
        return True
    except Exception as e:
        logger.error(f"❌ S3 delete failed: {str(e)}")
        return False

def generate_presigned_url(key, expires=3600):
    """Generate presigned URL for private S3 objects"""
    if not S3_ENABLED or not key:
        return None
    
    try:
        return s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': WASABI_CONFIG['bucket'], 'Key': key},
            ExpiresIn=expires
        )
    except Exception as e:
        logger.error(f"❌ Presigned URL generation failed: {str(e)}")
        return None

# =========== UTILITY FUNCTIONS ===========
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate Kenyan phone number"""
    pattern = r'^254[17]\d{8}$'
    return re.match(pattern, phone) is not None

def sanitize_input(text, max_length=1000):
    """Sanitize user input"""
    if not text:
        return text
    text = str(text).strip()
    if len(text) > max_length:
        text = text[:max_length]
    return text

def generate_transaction_id():
    """Generate unique transaction ID"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_str = uuid.uuid4().hex[:8].upper()
    return f"BFC{timestamp}{random_str}"

def parse_mpesa_message(message):
    """Parse MPesa message to extract transaction details"""
    try:
        # Clean message
        message = ' '.join(message.strip().split())
        
        # Pattern for MPesa messages
        patterns = [
            r'([A-Z0-9]{10})\s+Confirmed\.\s+Ksh([\d,]+\.\d{2})\s+paid\s+to\s+PETER\s+KINUTHIA\s+NGIGI',
            r'([A-Z0-9]{10})\s+Confirmed\.\s+Ksh([\d,]+\.\d{2})\s+sent\s+to\s+PETER\s+KINUTHIA\s+NGIGI',
            r'([A-Z0-9]{10}).*?Ksh([\d,]+\.\d{2}).*?PETER\s+KINUTHIA\s+NGIGI',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return {
                    'transaction_code': match.group(1).upper(),
                    'amount': float(match.group(2).replace(',', '')),
                    'recipient': 'PETER KINUTHIA NGIGI',
                    'is_valid': True
                }
        
        return {'is_valid': False, 'error': 'Invalid MPesa message format'}
    
    except Exception as e:
        logger.error(f"MPesa parse error: {str(e)}")
        return {'is_valid': False, 'error': 'Failed to parse message'}

def generate_qr_code(data):
    """Generate QR code image"""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    except Exception as e:
        logger.error(f"QR code generation error: {str(e)}")
        return None

# =========== MIDDLEWARE ===========
@app.before_request
def before_request():
    """Process requests before routing"""
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        return '', 200
    
    # Log request
    if not request.path.startswith('/static') and not request.path == '/':
        logger.debug(f"{request.method} {request.path} - {request.remote_addr}")
    
    # Detect platform from headers
    platform = request.headers.get('X-Platform', 'web').lower()
    request.environ['PLATFORM'] = platform

@app.after_request
def after_request(response):
    """Add headers to responses"""
    # CORS headers
    origin = request.headers.get('Origin')
    if origin and origin in ALLOWED_ORIGINS:
        response.headers.add('Access-Control-Allow-Origin', origin)
    
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Platform')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    
    # Security headers
    response.headers.add('X-Content-Type-Options', 'nosniff')
    response.headers.add('X-Frame-Options', 'DENY')
    response.headers.add('X-XSS-Protection', '1; mode=block')
    
    # Platform info
    platform = request.environ.get('PLATFORM', 'web')
    response.headers.add('X-Platform-Info', platform)
    
    return response

# =========== ERROR HANDLERS ===========
@app.errorhandler(400)
def bad_request_error(error):
    return jsonify({
        'success': False,
        'error': 'Bad Request',
        'message': str(error) if app.debug else 'Invalid request'
    }), 400

@app.errorhandler(401)
def unauthorized_error(error):
    return jsonify({
        'success': False,
        'error': 'Unauthorized',
        'message': 'Authentication required'
    }), 401

@app.errorhandler(403)
def forbidden_error(error):
    return jsonify({
        'success': False,
        'error': 'Forbidden',
        'message': 'Access denied'
    }), 403

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({
        'success': False,
        'error': 'Not Found',
        'message': 'Resource not found'
    }), 404

@app.errorhandler(413)
def payload_too_large(error):
    return jsonify({
        'success': False,
        'error': 'Payload Too Large',
        'message': 'File size exceeds limit'
    }), 413

@app.errorhandler(429)
def too_many_requests(error):
    return jsonify({
        'success': False,
        'error': 'Too Many Requests',
        'message': 'Rate limit exceeded'
    }), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    logger.error(traceback.format_exc())
    
    return jsonify({
        'success': False,
        'error': 'Internal Server Error',
        'message': 'Something went wrong' if not app.debug else str(error)
    }), 500

# =========== HEALTH & INFO ENDPOINTS ===========
@app.route('/')
def index():
    """Serve main page"""
    return render_template('index.html')

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test database
        db_test = execute_query("SELECT 1 as test", fetchone=True)
        
        return jsonify({
            'success': True,
            'status': 'healthy',
            'service': 'B/F Cinema Streaming Platform',
            'version': '3.0.0',
            'timestamp': datetime.now().isoformat(),
            'platform': request.environ.get('PLATFORM', 'web'),
            'environment': 'production' if IS_PRODUCTION else 'development',
            'database': 'connected' if db_test else 'disconnected',
            'storage': 'wasabi' if S3_ENABLED else 'local',
            'features': {
                'authentication': True,
                'streaming': True,
                'payments': True,
                'downloads': True,
                'favorites': True,
                'reviews': True
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/api/info', methods=['GET'])
def api_info():
    """API information endpoint"""
    return jsonify({
        'success': True,
        'name': 'B/F Cinema API',
        'version': '3.0.0',
        'documentation': '/docs' if os.path.exists('templates/docs.html') else None,
        'endpoints': {
            'auth': '/api/auth/*',
            'movies': '/api/movies/*',
            'payments': '/api/payments/*',
            'user': '/api/user/*',
            'admin': '/api/admin/*'
        },
        'support': {
            'email': 'bfCinemamovies@gmail.com',
            'phone': '+254 700 505325'
        }
    })

# =========== AUTHENTICATION ENDPOINTS ===========
@app.route('/api/auth/register', methods=['POST'])
def register_user():
    """Register new user"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Extract and validate data
        name = sanitize_input(data.get('name'))
        email = sanitize_input(data.get('email', '')).lower()
        phone = sanitize_input(data.get('phone', ''))
        password = data.get('password')
        platform = request.environ.get('PLATFORM', 'web')
        
        # Validation
        if not name or not email or not password:
            return jsonify({'success': False, 'error': 'Name, email, and password are required'}), 400
        
        if not validate_email(email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
        
        if phone and not validate_phone(phone):
            return jsonify({'success': False, 'error': 'Invalid phone number. Use format: 2547XXXXXXXX'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        # Check if user exists
        existing_user = execute_query(
            "SELECT id FROM users WHERE email = ?",
            (email,),
            fetchone=True
        )
        
        if existing_user:
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        # Create user
        password_hash = generate_password_hash(password)
        user_id = execute_query(
            '''
            INSERT INTO users (name, email, phone, password_hash, platform, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (name, email, phone, password_hash, platform, datetime.now())
        )
        
        # Create default settings
        execute_query(
            '''
            INSERT INTO user_settings (user_id, created_at)
            VALUES (?, ?)
            ''',
            (user_id, datetime.now())
        )
        
        # Create session
        session['user_id'] = user_id
        session['user_email'] = email
        session['user_name'] = name
        session['is_admin'] = False
        session['platform'] = platform
        
        logger.info(f"👤 New user registered: {email} ({platform})")
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': {
                'id': user_id,
                'name': name,
                'email': email,
                'phone': phone,
                'isAdmin': False,
                'platform': platform
            }
        })
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'success': False, 'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    """User login"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        email = sanitize_input(data.get('email', '')).lower()
        password = data.get('password')
        platform = request.environ.get('PLATFORM', 'web')
        
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400
        
        # Check admin login
        admin_email = 'BFCM2026@GMAIL.COM'
        admin_password = os.getenv('ADMIN_PASSWORD', 'Admin@2026')
        
        if email == admin_email.lower() and password == admin_password:
            session.clear()
            session['user_id'] = 'admin_001'
            session['user_email'] = admin_email
            session['user_name'] = 'Administrator'
            session['is_admin'] = True
            session['platform'] = platform
            
            logger.info(f"👑 Admin logged in via {platform}")
            
            return jsonify({
                'success': True,
                'message': 'Admin login successful',
                'user': {
                    'id': 'admin_001',
                    'name': 'Administrator',
                    'email': admin_email,
                    'isAdmin': True,
                    'platform': platform
                }
            })
        
        # Check regular user
        user = execute_query(
            '''
            SELECT id, name, email, phone, password_hash, is_admin, is_active, platform
            FROM users 
            WHERE email = ? AND is_active = 1
            ''',
            (email,),
            fetchone=True
        )
        
        if not user:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        if not check_password_hash(user['password_hash'], password):
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        # Update last login and platform
        execute_query(
            '''
            UPDATE users 
            SET last_login = ?, platform = ?
            WHERE id = ?
            ''',
            (datetime.now(), platform, user['id'])
        )
        
        # Create session
        session.clear()
        session['user_id'] = user['id']
        session['user_email'] = user['email']
        session['user_name'] = user['name']
        session['is_admin'] = bool(user['is_admin'])
        session['platform'] = platform
        
        logger.info(f"👤 User logged in: {email} ({platform})")
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'phone': user['phone'],
                'isAdmin': bool(user['is_admin']),
                'platform': platform
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'error': 'Login failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout_user():
    """User logout"""
    try:
        user_email = session.get('user_email')
        platform = session.get('platform', 'web')
        
        session.clear()
        
        if user_email:
            logger.info(f"👤 User logged out: {user_email} ({platform})")
        
        return jsonify({
            'success': True,
            'message': 'Logout successful'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Logout failed'}), 500

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    """Check authentication status"""
    try:
        if 'user_id' in session:
            user_id = session['user_id']
            
            if user_id == 'admin_001':
                return jsonify({
                    'success': True,
                    'authenticated': True,
                    'user': {
                        'id': 'admin_001',
                        'name': 'Administrator',
                        'email': 'BFCM2026@GMAIL.COM',
                        'isAdmin': True,
                        'platform': session.get('platform', 'web')
                    }
                })
            
            user = execute_query(
                '''
                SELECT id, name, email, phone, is_admin, is_active
                FROM users 
                WHERE id = ? AND is_active = 1
                ''',
                (user_id,),
                fetchone=True
            )
            
            if user:
                return jsonify({
                    'success': True,
                    'authenticated': True,
                    'user': {
                        'id': user['id'],
                        'name': user['name'],
                        'email': user['email'],
                        'phone': user['phone'],
                        'isAdmin': bool(user['is_admin']),
                        'platform': session.get('platform', 'web')
                    }
                })
        
        return jsonify({
            'success': True,
            'authenticated': False
        })
        
    except Exception as e:
        logger.error(f"Auth status error: {str(e)}")
        return jsonify({'success': False, 'error': 'Authentication check failed'}), 500

# =========== MOVIE ENDPOINTS ===========
@app.route('/api/movies', methods=['GET'])
def get_movies():
    """Get all movies with pagination and filters"""
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        genre = request.args.get('genre')
        year = request.args.get('year')
        featured = request.args.get('featured', '').lower() == 'true'
        trending = request.args.get('trending', '').lower() == 'true'
        free = request.args.get('free', '').lower() == 'true'
        search = request.args.get('search', '').strip()
        
        # Calculate offset
        offset = (page - 1) * limit
        
        # Build query
        query = '''
            SELECT id, title, description, year, genre, duration, 
                   director, rating, price, video_url, poster_url, 
                   trailer_url, is_featured, is_trending, is_free,
                   views, downloads, likes, uploaded_at
            FROM movies 
            WHERE is_active = 1
        '''
        params = []
        
        # Add filters
        if genre:
            query += " AND genre LIKE ?"
            params.append(f'%{genre}%')
        
        if year:
            query += " AND year = ?"
            params.append(year)
        
        if featured:
            query += " AND is_featured = 1"
        
        if trending:
            query += " AND is_trending = 1"
        
        if free:
            query += " AND is_free = 1"
        
        if search:
            query += " AND (title LIKE ? OR description LIKE ? OR director LIKE ? OR cast LIKE ?)"
            search_term = f'%{search}%'
            params.extend([search_term, search_term, search_term, search_term])
        
        # Add sorting and pagination
        query += " ORDER BY uploaded_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        # Execute query
        movies = execute_query(query, params, fetchall=True)
        
        # Get total count for pagination
        count_query = "SELECT COUNT(*) as total FROM movies WHERE is_active = 1"
        if len(params) > 2:  # Remove LIMIT and OFFSET params
            count_params = params[:-2]
            # Rebuild count query with filters
            count_query = count_query.replace("WHERE is_active = 1", 
                                            "WHERE is_active = 1" + query.split("WHERE is_active = 1")[1].split("ORDER BY")[0])
        
        total_result = execute_query(count_query, params[:-2] if len(params) > 2 else [], fetchone=True)
        total = total_result['total'] if total_result else 0
        
        # Check access for each movie if user is authenticated
        user_id = session.get('user_id')
        movies_with_access = []
        
        for movie in movies:
            has_access = False
            
            if user_id:
                # Admin has access to everything
                if user_id == 'admin_001':
                    has_access = True
                else:
                    # Check if movie is free
                    if movie['is_free']:
                        has_access = True
                    else:
                        # Check if user has purchased access
                        access = execute_query(
                            "SELECT id FROM user_access WHERE user_id = ? AND movie_id = ? AND is_active = 1",
                            (user_id, movie['id']),
                            fetchone=True
                        )
                        has_access = access is not None
            else:
                # Non-authenticated users only get free movies
                has_access = bool(movie['is_free'])
            
            movies_with_access.append({
                **movie,
                'hasAccess': has_access,
                'price': float(movie['price']),
                'rating': float(movie['rating']) if movie['rating'] else 0.0
            })
        
        return jsonify({
            'success': True,
            'movies': movies_with_access,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'pages': (total + limit - 1) // limit
            },
            'filters': {
                'genre': genre,
                'year': year,
                'featured': featured,
                'trending': trending,
                'free': free,
                'search': search
            }
        })
        
    except Exception as e:
        logger.error(f"Get movies error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load movies'}), 500

@app.route('/api/movies/<int:movie_id>', methods=['GET'])
def get_movie(movie_id):
    """Get movie details"""
    try:
        # Get movie
        movie = execute_query(
            '''
            SELECT m.*, u.name as uploader_name
            FROM movies m
            LEFT JOIN users u ON m.uploader_id = u.id
            WHERE m.id = ? AND m.is_active = 1
            ''',
            (movie_id,),
            fetchone=True
        )
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        # Check if user has access
        user_id = session.get('user_id')
        has_access = False
        
        if user_id:
            if user_id == 'admin_001':
                has_access = True
            elif movie['is_free']:
                has_access = True
            else:
                access = execute_query(
                    "SELECT id FROM user_access WHERE user_id = ? AND movie_id = ? AND is_active = 1",
                    (user_id, movie_id),
                    fetchone=True
                )
                has_access = access is not None
        else:
            has_access = bool(movie['is_free'])
        
        # Get reviews
        reviews = execute_query(
            '''
            SELECT r.*, u.name as user_name
            FROM reviews r
            JOIN users u ON r.user_id = u.id
            WHERE r.movie_id = ?
            ORDER BY r.created_at DESC
            LIMIT 10
            ''',
            (movie_id,),
            fetchall=True
        )
        
        # Get similar movies
        similar_movies = execute_query(
            '''
            SELECT id, title, poster_url, year, rating, duration
            FROM movies 
            WHERE genre LIKE ? AND id != ? AND is_active = 1
            ORDER BY RANDOM()
            LIMIT 6
            ''',
            (f'%{movie["genre"]}%' if movie.get('genre') else '%', movie_id),
            fetchall=True
        )
        
        # Parse subtitles if they exist
        subtitles = []
        if movie.get('subtitles'):
            try:
                subtitles = json.loads(movie['subtitles'])
            except:
                subtitles = []
        
        movie_data = {
            'id': movie['id'],
            'title': movie['title'],
            'description': movie['description'],
            'year': movie['year'],
            'genre': movie['genre'],
            'duration': movie['duration'],
            'director': movie['director'],
            'cast': movie['cast'],
            'rating': float(movie['rating']) if movie['rating'] else 0.0,
            'price': float(movie['price']),
            'videoUrl': movie['video_url'],
            'posterUrl': movie['poster_url'],
            'trailerUrl': movie['trailer_url'],
            'isFeatured': bool(movie['is_featured']),
            'isTrending': bool(movie['is_trending']),
            'isFree': bool(movie['is_free']),
            'ageRating': movie['age_rating'],
            'views': movie['views'],
            'downloads': movie['downloads'],
            'likes': movie['likes'],
            'uploader': movie['uploader_name'],
            'uploadedAt': movie['uploaded_at'],
            'resolution': movie['resolution'],
            'language': movie['language'],
            'subtitles': subtitles,
            'fileSize': movie['file_size'],
            'durationSeconds': movie['duration_seconds'],
            'hasAccess': has_access,
            'reviews': reviews,
            'similarMovies': similar_movies
        }
        
        return jsonify({
            'success': True,
            'movie': movie_data
        })
        
    except Exception as e:
        logger.error(f"Get movie error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load movie details'}), 500

@app.route('/api/movies/<int:movie_id>/watch', methods=['POST'])
def watch_movie(movie_id):
    """Record movie watch"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        data = request.get_json()
        progress_seconds = data.get('progress_seconds', 0)
        duration_seconds = data.get('duration_seconds', 0)
        platform = request.environ.get('PLATFORM', 'web')
        
        # Check access
        user_id = session['user_id']
        
        if user_id != 'admin_001':
            movie = execute_query(
                "SELECT is_free FROM movies WHERE id = ? AND is_active = 1",
                (movie_id,),
                fetchone=True
            )
            
            if not movie:
                return jsonify({'success': False, 'error': 'Movie not found'}), 404
            
            if not movie['is_free']:
                access = execute_query(
                    "SELECT id FROM user_access WHERE user_id = ? AND movie_id = ? AND is_active = 1",
                    (user_id, movie_id),
                    fetchone=True
                )
                
                if not access:
                    return jsonify({'success': False, 'error': 'Access denied. Purchase required.'}), 403
        
        # Calculate percentage
        percentage = 0
        if duration_seconds > 0:
            percentage = min(100, int((progress_seconds / duration_seconds) * 100))
        
        # Record watch history
        watch_id = execute_query(
            '''
            INSERT INTO watch_history 
            (user_id, movie_id, progress_seconds, duration_seconds, percentage_complete, platform, started_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (user_id, movie_id, progress_seconds, duration_seconds, percentage, platform, datetime.now())
        )
        
        # Update movie views
        execute_query(
            "UPDATE movies SET views = views + 1 WHERE id = ?",
            (movie_id,)
        )
        
        # Update user access watch count
        if user_id != 'admin_001':
            execute_query(
                '''
                UPDATE user_access 
                SET watch_count = watch_count + 1, 
                    last_watched = ?,
                    progress_seconds = GREATEST(progress_seconds, ?)
                WHERE user_id = ? AND movie_id = ?
                ''',
                (datetime.now(), progress_seconds, user_id, movie_id)
            )
        
        return jsonify({
            'success': True,
            'message': 'Watch recorded',
            'watchId': watch_id,
            'percentage': percentage
        })
        
    except Exception as e:
        logger.error(f"Watch movie error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to record watch'}), 500

@app.route('/api/movies/<int:movie_id>/stream', methods=['GET'])
def stream_movie(movie_id):
    """Get movie streaming URL"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        # Check access
        user_id = session['user_id']
        
        if user_id != 'admin_001':
            movie = execute_query(
                "SELECT video_url, is_free FROM movies WHERE id = ? AND is_active = 1",
                (movie_id,),
                fetchone=True
            )
            
            if not movie:
                return jsonify({'success': False, 'error': 'Movie not found'}), 404
            
            if not movie['is_free']:
                access = execute_query(
                    "SELECT id FROM user_access WHERE user_id = ? AND movie_id = ? AND is_active = 1",
                    (user_id, movie_id),
                    fetchone=True
                )
                
                if not access:
                    return jsonify({'success': False, 'error': 'Access denied. Purchase required.'}), 403
        
        # Get video URL
        movie = execute_query(
            "SELECT video_url, video_key, title, file_type FROM movies WHERE id = ?",
            (movie_id,),
            fetchone=True
        )
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        # Generate streaming URL
        stream_url = movie['video_url']
        
        # If video_key exists and S3 is enabled, generate presigned URL
        if movie['video_key'] and S3_ENABLED:
            presigned_url = generate_presigned_url(movie['video_key'], expires=7200)  # 2 hours
            if presigned_url:
                stream_url = presigned_url
        
        return jsonify({
            'success': True,
            'streamUrl': stream_url,
            'contentType': movie.get('file_type', 'video/mp4'),
            'movieTitle': movie['title'],
            'expiresIn': 7200  # 2 hours in seconds
        })
        
    except Exception as e:
        logger.error(f"Stream movie error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to get stream URL'}), 500

# =========== PAYMENT ENDPOINTS ===========
@app.route('/api/payments/initiate', methods=['POST'])
def initiate_payment():
    """Initiate payment for movie"""
    try:
        if 'user_id' not in session or session['user_id'] == 'admin_001':
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        data = request.get_json()
        movie_id = data.get('movie_id')
        phone = data.get('phone', '').strip()
        
        if not movie_id:
            return jsonify({'success': False, 'error': 'Movie ID is required'}), 400
        
        if not phone:
            return jsonify({'success': False, 'error': 'Phone number is required'}), 400
        
        if not validate_phone(phone):
            return jsonify({'success': False, 'error': 'Invalid phone number. Use format: 2547XXXXXXXX'}), 400
        
        # Get movie details
        movie = execute_query(
            "SELECT id, title, price FROM movies WHERE id = ? AND is_active = 1",
            (movie_id,),
            fetchone=True
        )
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        # Check if user already has access
        user_id = session['user_id']
        existing_access = execute_query(
            "SELECT id FROM user_access WHERE user_id = ? AND movie_id = ? AND is_active = 1",
            (user_id, movie_id),
            fetchone=True
        )
        
        if existing_access:
            return jsonify({'success': False, 'error': 'You already have access to this movie'}), 400
        
        # Generate transaction ID
        transaction_id = generate_transaction_id()
        
        # Create pending transaction
        trans_id = execute_query(
            '''
            INSERT INTO transactions 
            (transaction_id, user_id, movie_id, amount, phone_number, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'pending', ?)
            ''',
            (transaction_id, user_id, movie_id, float(movie['price']), phone, datetime.now())
        )
        
        # Generate payment instructions
        payment_instructions = {
            'amount': float(movie['price']),
            'phone': phone,
            'businessNumber': '7048202',  # Peter Kinuthia Ngigi's till number
            'businessName': 'PETER KINUTHIA NGIGI',
            'accountNumber': 'BFCINEMA',
            'transactionId': transaction_id,
            'instructions': [
                '1. Go to M-Pesa on your phone',
                '2. Select "Lipa na M-Pesa"',
                '3. Select "Pay Bill"',
                '4. Enter Business Number: 7048202',
                '5. Enter Account Number: BFCINEMA',
                '6. Enter Amount: KES 30.00',
                '7. Enter your M-Pesa PIN',
                '8. Wait for confirmation message'
            ]
        }
        
        return jsonify({
            'success': True,
            'message': 'Payment initiated',
            'transactionId': transaction_id,
            'transactionDbId': trans_id,
            'paymentInstructions': payment_instructions,
            'movie': {
                'id': movie['id'],
                'title': movie['title'],
                'price': float(movie['price'])
            }
        })
        
    except Exception as e:
        logger.error(f"Initiate payment error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to initiate payment'}), 500

@app.route('/api/payments/verify', methods=['POST'])
def verify_payment():
    """Verify MPesa payment"""
    try:
        if 'user_id' not in session or session['user_id'] == 'admin_001':
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        data = request.get_json()
        transaction_id = data.get('transaction_id', '').strip()
        mpesa_message = data.get('mpesa_message', '').strip()
        
        if not transaction_id or not mpesa_message:
            return jsonify({'success': False, 'error': 'Transaction ID and MPesa message are required'}), 400
        
        # Get transaction
        transaction = execute_query(
            '''
            SELECT t.*, m.title as movie_title, m.price, u.email, u.name
            FROM transactions t
            JOIN movies m ON t.movie_id = m.id
            JOIN users u ON t.user_id = u.id
            WHERE t.transaction_id = ? AND t.user_id = ?
            ''',
            (transaction_id, session['user_id']),
            fetchone=True
        )
        
        if not transaction:
            return jsonify({'success': False, 'error': 'Transaction not found'}), 404
        
        if transaction['status'] == 'verified':
            return jsonify({'success': False, 'error': 'Payment already verified'}), 400
        
        if transaction['status'] == 'failed':
            return jsonify({'success': False, 'error': 'Payment was marked as failed'}), 400
        
        # Parse MPesa message
        parsed = parse_mpesa_message(mpesa_message)
        
        if not parsed['is_valid']:
            # Mark as failed
            execute_query(
                "UPDATE transactions SET status = 'failed', notes = ? WHERE id = ?",
                (parsed.get('error', 'Invalid MPesa message'), transaction['id'])
            )
            return jsonify({'success': False, 'error': parsed.get('error', 'Invalid MPesa message')}), 400
        
        # Verify amount matches
        expected_amount = float(transaction['amount'])
        received_amount = parsed['amount']
        
        if abs(received_amount - expected_amount) > 0.01:
            error_msg = f'Amount mismatch. Expected: KES {expected_amount:.2f}, Received: KES {received_amount:.2f}'
            execute_query(
                "UPDATE transactions SET status = 'failed', notes = ? WHERE id = ?",
                (error_msg, transaction['id'])
            )
            return jsonify({'success': False, 'error': error_msg}), 400
        
        # Check if MPesa code already used
        if parsed.get('transaction_code'):
            existing = execute_query(
                "SELECT id FROM transactions WHERE mpesa_code = ? AND status = 'verified'",
                (parsed['transaction_code'],),
                fetchone=True
            )
            
            if existing:
                execute_query(
                    "UPDATE transactions SET status = 'failed', notes = ? WHERE id = ?",
                    ('MPesa code already used', transaction['id'])
                )
                return jsonify({'success': False, 'error': 'This MPesa code has already been used'}), 400
        
        # Verify payment
        execute_query(
            '''
            UPDATE transactions 
            SET status = 'verified', 
                mpesa_code = ?,
                receipt_number = ?,
                payment_date = ?,
                verified_at = ?,
                notes = 'Payment verified successfully'
            WHERE id = ?
            ''',
            (
                parsed.get('transaction_code'),
                parsed.get('transaction_code'),
                datetime.now(),
                datetime.now(),
                transaction['id']
            )
        )
        
        # Grant access to movie
        execute_query(
            '''
            INSERT INTO user_access (user_id, movie_id, transaction_id, is_active)
            VALUES (?, ?, ?, 1)
            ''',
            (session['user_id'], transaction['movie_id'], transaction['id'])
        )
        
        # Update movie downloads count
        execute_query(
            "UPDATE movies SET downloads = downloads + 1 WHERE id = ?",
            (transaction['movie_id'],)
        )
        
        # Record download
        execute_query(
            '''
            INSERT INTO downloads (user_id, movie_id, downloaded_at, platform)
            VALUES (?, ?, ?, ?)
            ''',
            (session['user_id'], transaction['movie_id'], datetime.now(), request.environ.get('PLATFORM', 'web'))
        )
        
        # Generate receipt
        receipt = {
            'transactionId': transaction['transaction_id'],
            'mpesaCode': parsed.get('transaction_code', transaction['transaction_id']),
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'customer': transaction['name'],
            'email': transaction['email'],
            'phone': transaction['phone_number'],
            'movie': transaction['movie_title'],
            'amount': float(transaction['amount']),
            'status': 'verified',
            'receiptNumber': f"BFC{transaction['id']:06d}",
            'qrCode': generate_qr_code(f"BFCINEMA|{transaction['transaction_id']}|{parsed.get('transaction_code', '')}")
        }
        
        logger.info(f"💰 Payment verified: {transaction['transaction_id']} for movie {transaction['movie_title']}")
        
        return jsonify({
            'success': True,
            'message': 'Payment verified successfully! Movie added to your library.',
            'receipt': receipt,
            'accessGranted': True,
            'movieId': transaction['movie_id']
        })
        
    except Exception as e:
        logger.error(f"Verify payment error: {str(e)}")
        return jsonify({'success': False, 'error': 'Payment verification failed'}), 500

@app.route('/api/payments/transactions', methods=['GET'])
def get_user_transactions():
    """Get user's transactions"""
    try:
        if 'user_id' not in session or session['user_id'] == 'admin_001':
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        user_id = session['user_id']
        
        transactions = execute_query(
            '''
            SELECT t.*, m.title as movie_title, m.poster_url
            FROM transactions t
            JOIN movies m ON t.movie_id = m.id
            WHERE t.user_id = ?
            ORDER BY t.created_at DESC
            ''',
            (user_id,),
            fetchall=True
        )
        
        return jsonify({
            'success': True,
            'transactions': transactions
        })
        
    except Exception as e:
        logger.error(f"Get transactions error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load transactions'}), 500

# =========== USER PROFILE ENDPOINTS ===========
@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    """Get user profile"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        user_id = session['user_id']
        
        if user_id == 'admin_001':
            return jsonify({
                'success': True,
                'profile': {
                    'id': 'admin_001',
                    'name': 'Administrator',
                    'email': 'BFCM2026@GMAIL.COM',
                    'phone': '+254700505325',
                    'isAdmin': True,
                    'createdAt': datetime.now().isoformat(),
                    'platform': 'web'
                }
            })
        
        # Get user profile
        profile = execute_query(
            '''
            SELECT u.*, s.language, s.theme, s.video_quality
            FROM users u
            LEFT JOIN user_settings s ON u.id = s.user_id
            WHERE u.id = ?
            ''',
            (user_id,),
            fetchone=True
        )
        
        if not profile:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Get user stats
        stats = execute_query(
            '''
            SELECT 
                COUNT(DISTINCT ua.movie_id) as movies_purchased,
                COUNT(DISTINCT d.id) as movies_downloaded,
                COUNT(DISTINCT wh.id) as movies_watched,
                SUM(t.amount) as total_spent,
                COUNT(DISTINCT f.movie_id) as favorites_count
            FROM users u
            LEFT JOIN user_access ua ON u.id = ua.user_id AND ua.is_active = 1
            LEFT JOIN downloads d ON u.id = d.user_id
            LEFT JOIN watch_history wh ON u.id = wh.user_id
            LEFT JOIN transactions t ON u.id = t.user_id AND t.status = 'verified'
            LEFT JOIN favorites f ON u.id = f.user_id
            WHERE u.id = ?
            ''',
            (user_id,),
            fetchone=True
        )
        
        # Get recent activity
        recent_activity = execute_query(
            '''
            (SELECT 'watch' as type, wh.started_at as date, m.title, m.poster_url
             FROM watch_history wh
             JOIN movies m ON wh.movie_id = m.id
             WHERE wh.user_id = ?
             ORDER BY wh.started_at DESC
             LIMIT 5)
            UNION
            (SELECT 'download' as type, d.downloaded_at as date, m.title, m.poster_url
             FROM downloads d
             JOIN movies m ON d.movie_id = m.id
             WHERE d.user_id = ?
             ORDER BY d.downloaded_at DESC
             LIMIT 5)
            UNION
            (SELECT 'purchase' as type, t.verified_at as date, m.title, m.poster_url
             FROM transactions t
             JOIN movies m ON t.movie_id = m.id
             WHERE t.user_id = ? AND t.status = 'verified'
             ORDER BY t.verified_at DESC
             LIMIT 5)
            ORDER BY date DESC
            LIMIT 10
            ''',
            (user_id, user_id, user_id),
            fetchall=True
        )
        
        profile_data = {
            'id': profile['id'],
            'name': profile['name'],
            'email': profile['email'],
            'phone': profile['phone'],
            'avatarUrl': profile['avatar_url'],
            'isAdmin': bool(profile['is_admin']),
            'isActive': bool(profile['is_active']),
            'emailVerified': bool(profile['email_verified']),
            'phoneVerified': bool(profile['phone_verified']),
            'createdAt': profile['created_at'],
            'lastLogin': profile['last_login'],
            'platform': profile['platform'],
            'settings': {
                'language': profile['language'] or 'en',
                'theme': profile['theme'] or 'dark',
                'videoQuality': profile['video_quality'] or 'auto'
            },
            'stats': {
                'moviesPurchased': stats['movies_purchased'] or 0,
                'moviesDownloaded': stats['movies_downloaded'] or 0,
                'moviesWatched': stats['movies_watched'] or 0,
                'totalSpent': float(stats['total_spent'] or 0),
                'favoritesCount': stats['favorites_count'] or 0
            },
            'recentActivity': recent_activity
        }
        
        return jsonify({
            'success': True,
            'profile': profile_data
        })
        
    except Exception as e:
        logger.error(f"Get profile error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load profile'}), 500

@app.route('/api/user/library', methods=['GET'])
def get_user_library():
    """Get user's movie library (purchased movies)"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        user_id = session['user_id']
        
        # Get purchased movies with access
        library = execute_query(
            '''
            SELECT m.*, ua.access_granted_at, ua.last_watched, ua.watch_count, ua.progress_seconds
            FROM movies m
            JOIN user_access ua ON m.id = ua.movie_id
            WHERE ua.user_id = ? AND ua.is_active = 1 AND m.is_active = 1
            ORDER BY ua.access_granted_at DESC
            ''',
            (user_id,),
            fetchall=True
        )
        
        # Get free movies user has watched
        free_movies = execute_query(
            '''
            SELECT DISTINCT m.*, MAX(wh.started_at) as last_watched
            FROM movies m
            JOIN watch_history wh ON m.id = wh.movie_id
            WHERE wh.user_id = ? AND m.is_free = 1 AND m.is_active = 1
            GROUP BY m.id
            ORDER BY last_watched DESC
            ''',
            (user_id,),
            fetchall=True
        )
        
        # Get favorites
        favorites = execute_query(
            '''
            SELECT m.*, f.added_at
            FROM movies m
            JOIN favorites f ON m.id = f.movie_id
            WHERE f.user_id = ? AND m.is_active = 1
            ORDER BY f.added_at DESC
            ''',
            (user_id,),
            fetchall=True
        )
        
        return jsonify({
            'success': True,
            'library': {
                'purchased': library,
                'free': free_movies,
                'favorites': favorites
            }
        })
        
    except Exception as e:
        logger.error(f"Get library error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load library'}), 500

@app.route('/api/user/favorites/<int:movie_id>', methods=['POST'])
def toggle_favorite(movie_id):
    """Add/remove movie from favorites"""
    try:
        if 'user_id' not in session or session['user_id'] == 'admin_001':
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        user_id = session['user_id']
        
        # Check if movie exists
        movie = execute_query(
            "SELECT id FROM movies WHERE id = ? AND is_active = 1",
            (movie_id,),
            fetchone=True
        )
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        # Check if already favorited
        favorite = execute_query(
            "SELECT id FROM favorites WHERE user_id = ? AND movie_id = ?",
            (user_id, movie_id),
            fetchone=True
        )
        
        if favorite:
            # Remove from favorites
            execute_query(
                "DELETE FROM favorites WHERE user_id = ? AND movie_id = ?",
                (user_id, movie_id)
            )
            message = 'Removed from favorites'
            is_favorite = False
        else:
            # Add to favorites
            execute_query(
                "INSERT INTO favorites (user_id, movie_id, added_at) VALUES (?, ?, ?)",
                (user_id, movie_id, datetime.now())
            )
            message = 'Added to favorites'
            is_favorite = True
        
        return jsonify({
            'success': True,
            'message': message,
            'isFavorite': is_favorite
        })
        
    except Exception as e:
        logger.error(f"Toggle favorite error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to update favorites'}), 500

# =========== ADMIN ENDPOINTS ===========
@app.route('/api/admin/movies', methods=['POST'])
def admin_create_movie():
    """Create new movie (admin only)"""
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        data = request.get_json()
        
        # Extract and validate data
        required_fields = ['title', 'video_url']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'{field} is required'}), 400
        
        # Prepare movie data
        movie_data = {
            'title': sanitize_input(data['title'], 200),
            'description': sanitize_input(data.get('description', ''), 1000),
            'year': data.get('year'),
            'genre': sanitize_input(data.get('genre', ''), 100),
            'duration': sanitize_input(data.get('duration', ''), 50),
            'director': sanitize_input(data.get('director', ''), 100),
            'cast': sanitize_input(data.get('cast', ''), 500),
            'price': float(data.get('price', 30.00)),
            'video_url': data['video_url'],
            'video_key': data.get('video_key'),
            'poster_url': data.get('poster_url'),
            'poster_key': data.get('poster_key'),
            'trailer_url': data.get('trailer_url'),
            'is_featured': 1 if data.get('is_featured') else 0,
            'is_trending': 1 if data.get('is_trending') else 0,
            'is_free': 1 if data.get('is_free') else 0,
            'age_rating': sanitize_input(data.get('age_rating', 'PG-13'), 10),
            'file_size': data.get('file_size'),
            'duration_seconds': data.get('duration_seconds'),
            'resolution': sanitize_input(data.get('resolution', '1080p'), 20),
            'language': sanitize_input(data.get('language', 'English'), 50),
            'subtitles': json.dumps(data.get('subtitles', [])),
            'uploader_id': session['user_id'] if session['user_id'] != 'admin_001' else None,
            'uploaded_at': datetime.now(),
            'updated_at': datetime.now()
        }
        
        # Insert movie
        columns = ', '.join(movie_data.keys())
        placeholders = ', '.join(['?' for _ in movie_data])
        values = list(movie_data.values())
        
        movie_id = execute_query(
            f"INSERT INTO movies ({columns}) VALUES ({placeholders})",
            values
        )
        
        logger.info(f"🎬 Movie created by admin: {movie_data['title']} (ID: {movie_id})")
        
        return jsonify({
            'success': True,
            'message': 'Movie created successfully',
            'movieId': movie_id
        })
        
    except Exception as e:
        logger.error(f"Create movie error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to create movie'}), 500

@app.route('/api/admin/movies/<int:movie_id>', methods=['PUT'])
def admin_update_movie(movie_id):
    """Update movie (admin only)"""
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        data = request.get_json()
        
        # Check if movie exists
        movie = execute_query(
            "SELECT id FROM movies WHERE id = ?",
            (movie_id,),
            fetchone=True
        )
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        # Prepare update data
        update_fields = []
        update_values = []
        
        field_mapping = {
            'title': ('title', str, 200),
            'description': ('description', str, 1000),
            'year': ('year', int),
            'genre': ('genre', str, 100),
            'duration': ('duration', str, 50),
            'director': ('director', str, 100),
            'cast': ('cast', str, 500),
            'price': ('price', float),
            'video_url': ('video_url', str),
            'video_key': ('video_key', str),
            'poster_url': ('poster_url', str),
            'poster_key': ('poster_key', str),
            'trailer_url': ('trailer_url', str),
            'is_featured': ('is_featured', bool),
            'is_trending': ('is_trending', bool),
            'is_free': ('is_free', bool),
            'age_rating': ('age_rating', str, 10),
            'file_size': ('file_size', int),
            'duration_seconds': ('duration_seconds', int),
            'resolution': ('resolution', str, 20),
            'language': ('language', str, 50),
            'subtitles': ('subtitles', list),
            'is_active': ('is_active', bool)
        }
        
        for key, value in data.items():
            if key in field_mapping:
                db_key, value_type, *max_length = field_mapping[key]
                
                # Convert value based on type
                if value_type == bool:
                    value = 1 if value else 0
                elif value_type == float:
                    value = float(value)
                elif value_type == int:
                    value = int(value)
                elif value_type == list:
                    value = json.dumps(value)
                elif value_type == str and max_length:
                    value = sanitize_input(value, max_length[0])
                
                update_fields.append(f"{db_key} = ?")
                update_values.append(value)
        
        if not update_fields:
            return jsonify({'success': False, 'error': 'No valid fields to update'}), 400
        
        # Add updated_at timestamp
        update_fields.append("updated_at = ?")
        update_values.append(datetime.now())
        
        # Add movie_id for WHERE clause
        update_values.append(movie_id)
        
        # Execute update
        query = f"UPDATE movies SET {', '.join(update_fields)} WHERE id = ?"
        execute_query(query, update_values)
        
        logger.info(f"📝 Movie updated by admin: ID {movie_id}")
        
        return jsonify({
            'success': True,
            'message': 'Movie updated successfully'
        })
        
    except Exception as e:
        logger.error(f"Update movie error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to update movie'}), 500

@app.route('/api/admin/movies/<int:movie_id>', methods=['DELETE'])
def admin_delete_movie(movie_id):
    """Delete movie (admin only)"""
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        # Check if movie exists
        movie = execute_query(
            "SELECT id, video_key, poster_key FROM movies WHERE id = ?",
            (movie_id,),
            fetchone=True
        )
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        # Delete from S3 if keys exist
        if movie['video_key'] and S3_ENABLED:
            delete_from_s3(movie['video_key'])
        
        if movie['poster_key'] and S3_ENABLED:
            delete_from_s3(movie['poster_key'])
        
        # Soft delete from database (mark as inactive)
        execute_query(
            "UPDATE movies SET is_active = 0, updated_at = ? WHERE id = ?",
            (datetime.now(), movie_id)
        )
        
        logger.info(f"🗑️ Movie soft-deleted by admin: ID {movie_id}")
        
        return jsonify({
            'success': True,
            'message': 'Movie deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Delete movie error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to delete movie'}), 500

@app.route('/api/admin/stats', methods=['GET'])
def admin_stats():
    """Get admin statistics"""
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        # Get basic counts
        stats = execute_query(
            '''
            SELECT 
                (SELECT COUNT(*) FROM movies WHERE is_active = 1) as total_movies,
                (SELECT COUNT(*) FROM users WHERE is_active = 1) as total_users,
                (SELECT COUNT(*) FROM transactions WHERE status = 'verified') as total_transactions,
                (SELECT SUM(amount) FROM transactions WHERE status = 'verified') as total_revenue,
                (SELECT COUNT(*) FROM watch_history) as total_watches,
                (SELECT COUNT(*) FROM downloads) as total_downloads
            ''',
            fetchone=True
        )
        
        # Get recent transactions
        recent_transactions = execute_query(
            '''
            SELECT t.*, u.name as user_name, u.email, m.title as movie_title
            FROM transactions t
            JOIN users u ON t.user_id = u.id
            JOIN movies m ON t.movie_id = m.id
            ORDER BY t.created_at DESC
            LIMIT 10
            ''',
            fetchall=True
        )
        
        # Get popular movies
        popular_movies = execute_query(
            '''
            SELECT id, title, poster_url, views, downloads, likes
            FROM movies 
            WHERE is_active = 1
            ORDER BY views DESC
            LIMIT 10
            ''',
            fetchall=True
        )
        
        # Get recent users
        recent_users = execute_query(
            '''
            SELECT id, name, email, phone, created_at, last_login, platform
            FROM users 
            WHERE is_active = 1
            ORDER BY created_at DESC
            LIMIT 10
            ''',
            fetchall=True
        )
        
        # Get revenue by day (last 7 days)
        revenue_by_day = execute_query(
            '''
            SELECT 
                DATE(verified_at) as date,
                COUNT(*) as transactions,
                SUM(amount) as revenue
            FROM transactions 
            WHERE status = 'verified' AND verified_at >= date('now', '-7 days')
            GROUP BY DATE(verified_at)
            ORDER BY date DESC
            ''',
            fetchall=True
        )
        
        return jsonify({
            'success': True,
            'stats': {
                'totalMovies': stats['total_movies'] or 0,
                'totalUsers': stats['total_users'] or 0,
                'totalTransactions': stats['total_transactions'] or 0,
                'totalRevenue': float(stats['total_revenue'] or 0),
                'totalWatches': stats['total_watches'] or 0,
                'totalDownloads': stats['total_downloads'] or 0
            },
            'recentTransactions': recent_transactions,
            'popularMovies': popular_movies,
            'recentUsers': recent_users,
            'revenueByDay': revenue_by_day
        })
        
    except Exception as e:
        logger.error(f"Admin stats error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load admin stats'}), 500

# =========== FILE UPLOAD ENDPOINTS ===========
@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload file to S3 or local storage"""
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        file_type = request.form.get('type', 'video')  # 'video' or 'poster'
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Validate file type
        allowed_extensions = {
            'video': ['.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm'],
            'poster': ['.jpg', '.jpeg', '.png', '.gif', '.webp']
        }
        
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in allowed_extensions.get(file_type, []):
            return jsonify({
                'success': False, 
                'error': f'Invalid file type for {file_type}. Allowed: {", ".join(allowed_extensions[file_type])}'
            }), 400
        
        # Generate unique filename
        unique_id = uuid.uuid4().hex[:8]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{file_type}_{timestamp}_{unique_id}{ext}"
        
        # Determine content type
        content_types = {
            '.mp4': 'video/mp4',
            '.mkv': 'video/x-matroska',
            '.avi': 'video/x-msvideo',
            '.mov': 'video/quicktime',
            '.wmv': 'video/x-ms-wmv',
            '.flv': 'video/x-flv',
            '.webm': 'video/webm',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp'
        }
        
        content_type = content_types.get(ext, 'application/octet-stream')
        
        # Upload to S3 if enabled
        if S3_ENABLED:
            # Create folder structure
            folder = 'videos' if file_type == 'video' else 'posters'
            s3_key = f"{folder}/{filename}"
            
            # Read file data
            file_data = file.read()
            
            # Upload to S3
            s3_url = upload_to_s3(
                file_data,
                s3_key,
                content_type=content_type,
                is_public=(file_type == 'poster')  # Posters are public
            )
            
            if not s3_url:
                return jsonify({'success': False, 'error': 'Failed to upload to storage'}), 500
            
            return jsonify({
                'success': True,
                'message': 'File uploaded successfully',
                'file': {
                    'originalName': file.filename,
                    'fileName': filename,
                    'fileType': file_type,
                    'contentType': content_type,
                    'size': len(file_data),
                    'url': s3_url,
                    'key': s3_key,
                    'storage': 's3'
                }
            })
        else:
            # Save locally (for development)
            upload_folder = 'uploads'
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)
            
            # Generate URL
            base_url = request.host_url.rstrip('/')
            file_url = f"{base_url}/{upload_folder}/{filename}"
            
            return jsonify({
                'success': True,
                'message': 'File uploaded successfully (local storage)',
                'file': {
                    'originalName': file.filename,
                    'fileName': filename,
                    'fileType': file_type,
                    'contentType': content_type,
                    'size': os.path.getsize(file_path),
                    'url': file_url,
                    'path': file_path,
                    'storage': 'local'
                }
            })
        
    except Exception as e:
        logger.error(f"File upload error: {str(e)}")
        return jsonify({'success': False, 'error': 'File upload failed'}), 500

# =========== STATIC FILE SERVING ===========
@app.route('/uploads/<path:filename>')
def serve_uploaded_file(filename):
    """Serve uploaded files from local storage"""
    try:
        upload_folder = 'uploads'
        return send_from_directory(upload_folder, filename)
    except Exception as e:
        return jsonify({'success': False, 'error': 'File not found'}), 404

# =========== MOBILE APP SPECIFIC ENDPOINTS ===========
@app.route('/api/mobile/config', methods=['GET'])
def mobile_config():
    """Get mobile app configuration"""
    return jsonify({
        'success': True,
        'config': {
            'appName': 'B/F Cinema',
            'version': '3.0.0',
            'apiBaseUrl': request.host_url.rstrip('/'),
            'features': {
                'streaming': True,
                'downloads': True,
                'offlineMode': True,
                'pushNotifications': False,
                'biometricAuth': False
            },
            'payment': {
                'businessNumber': '7048202',
                'businessName': 'PETER KINUTHIA NGIGI',
                'defaultAmount': 30.00,
                'currency': 'KES'
            },
            'support': {
                'email': 'bfCinemamovies@gmail.com',
                'phone': '+254 700 505325',
                'whatsapp': '+254700505325'
            }
        }
    })

@app.route('/api/mobile/check-update', methods=['GET'])
def mobile_check_update():
    """Check for mobile app updates"""
    current_version = request.args.get('version', '1.0.0')
    
    # In a real app, you would check against a database of versions
    latest_version = '3.0.0'
    
    needs_update = current_version != latest_version
    
    return jsonify({
        'success': True,
        'updateAvailable': needs_update,
        'currentVersion': current_version,
        'latestVersion': latest_version,
        'updateUrl': 'https://play.google.com/store/apps/details?id=com.bfcinema.app' if needs_update else None,
        'forceUpdate': False,
        'releaseNotes': [
            'Multi-platform support',
            'Improved video streaming',
            'Enhanced payment system',
            'Bug fixes and performance improvements'
        ] if needs_update else []
    })

# =========== APPLICATION STARTUP ===========
if __name__ == '__main__':
    # Print startup banner
    print("\n" + "="*70)
    print("🎬 B/F CINEMA STREAMING PLATFORM - MULTI-PLATFORM EDITION")
    print("="*70)
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 Environment: {'🚀 PRODUCTION' if IS_PRODUCTION else '🛠️ DEVELOPMENT'}")
    print(f"📁 Database: {get_db_path()}")
    print(f"☁️  Storage: {'✅ Wasabi S3' if S3_ENABLED else '⚠️ Local Storage'}")
    print(f"🔐 Admin: BFCM2026@GMAIL.COM")
    print("="*70)
    
    # Create necessary directories
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # Create basic index.html if doesn't exist
    if not os.path.exists('templates/index.html'):
        with open('templates/index.html', 'w') as f:
            f.write('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>B/F Cinema - Multi-Platform Streaming</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #0f0f0f 0%, #1a1a1a 100%);
            color: #ffffff;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 20px;
            text-align: center;
        }
        .container { max-width: 800px; width: 100%; }
        .logo { 
            font-size: 4rem; 
            font-weight: 900; 
            color: #e50914; 
            margin-bottom: 10px;
            text-shadow: 0 0 20px rgba(229, 9, 20, 0.5);
        }
        .tagline { 
            font-size: 1.2rem; 
            color: #aaa; 
            margin-bottom: 40px;
            font-weight: 300;
        }
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 40px 0;
        }
        .status-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 25px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s, border-color 0.3s;
        }
        .status-card:hover {
            transform: translateY(-5px);
            border-color: rgba(229, 9, 20, 0.3);
        }
        .card-title {
            font-size: 1.1rem;
            color: #ccc;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        .card-value {
            font-size: 2rem;
            font-weight: 700;
            color: #fff;
        }
        .card-desc {
            font-size: 0.9rem;
            color: #888;
            margin-top: 10px;
        }
        .platform-badges {
            display: flex;
            justify-content: center;
            gap: 15px;
            margin: 30px 0;
            flex-wrap: wrap;
        }
        .badge {
            background: rgba(229, 9, 20, 0.1);
            border: 1px solid rgba(229, 9, 20, 0.3);
            color: #e50914;
            padding: 10px 20px;
            border-radius: 25px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .api-info {
            margin-top: 40px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 10px;
            border-left: 4px solid #e50914;
        }
        .endpoint {
            font-family: 'Courier New', monospace;
            background: rgba(0, 0, 0, 0.3);
            padding: 8px 12px;
            border-radius: 5px;
            margin: 5px 0;
            font-size: 0.9rem;
            color: #4fc3f7;
        }
        .action-buttons {
            margin-top: 30px;
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
        }
        .btn {
            background: #e50914;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s, transform 0.2s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .btn:hover {
            background: #ff0a16;
            transform: scale(1.05);
        }
        .btn-secondary {
            background: transparent;
            border: 2px solid #e50914;
            color: #e50914;
        }
        .btn-secondary:hover {
            background: rgba(229, 9, 20, 0.1);
        }
        .footer {
            margin-top: 50px;
            color: #666;
            font-size: 0.9rem;
        }
        @media (max-width: 768px) {
            .logo { font-size: 3rem; }
            .status-grid { grid-template-columns: 1fr; }
            .action-buttons { flex-direction: column; }
            .btn { width: 100%; justify-content: center; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">B/F CINEMA</div>
        <div class="tagline">Stream Your Favorite Movies Anytime, Anywhere</div>
        
        <div class="platform-badges">
            <div class="badge">🌐 Web Ready</div>
            <div class="badge">📱 Mobile Optimized</div>
            <div class="badge">💻 Desktop Compatible</div>
        </div>
        
        <div class="status-grid">
            <div class="status-card">
                <div class="card-title">🚀 API Status</div>
                <div class="card-value" id="apiStatus">Checking...</div>
                <div class="card-desc">Backend Service</div>
            </div>
            <div class="status-card">
                <div class="card-title">💾 Database</div>
                <div class="card-value" id="dbStatus">Checking...</div>
                <div class="card-desc">SQLite Storage</div>
            </div>
            <div class="status-card">
                <div class="card-title">☁️ Storage</div>
                <div class="card-value" id="storageStatus">Checking...</div>
                <div class="card-desc">Wasabi S3</div>
            </div>
            <div class="status-card">
                <div class="card-title">👥 Users</div>
                <div class="card-value" id="usersCount">0</div>
                <div class="card-desc">Registered Accounts</div>
            </div>
        </div>
        
        <div class="api-info">
            <h3>📡 API Endpoints</h3>
            <div class="endpoint">GET /health - System Health</div>
            <div class="endpoint">GET /api/movies - Browse Movies</div>
            <div class="endpoint">POST /api/auth/login - User Login</div>
            <div class="endpoint">POST /api/payments/verify - MPesa Payment</div>
            <div class="endpoint">GET /api/user/profile - User Profile</div>
        </div>
        
        <div class="action-buttons">
            <button class="btn" onclick="checkHealth()">
                🔄 Check Health
            </button>
            <button class="btn btn-secondary" onclick="viewDocs()">
                📚 API Documentation
            </button>
            <button class="btn btn-secondary" onclick="testPayment()">
                💰 Test Payment Flow
            </button>
        </div>
        
        <div class="footer">
            <p>© 2024 B/F Cinema. All rights reserved.</p>
            <p>Support: bfCinemamovies@gmail.com | +254 700 505325</p>
        </div>
    </div>

    <script>
        async function checkHealth() {
            try {
                const response = await fetch('/health');
                const data = await response.json();
                
                document.getElementById('apiStatus').textContent = data.status.toUpperCase();
                document.getElementById('dbStatus').textContent = data.database.toUpperCase();
                document.getElementById('storageStatus').textContent = data.storage.toUpperCase();
                
                // Get users count
                const usersResponse = await fetch('/api/admin/stats');
                const usersData = await usersResponse.json();
                if (usersData.success) {
                    document.getElementById('usersCount').textContent = usersData.stats.totalUsers;
                }
                
                alert('✅ System is healthy!\n' + 
                      'Platform: ' + data.platform + '\n' +
                      'Version: ' + data.version);
            } catch (error) {
                alert('❌ Health check failed: ' + error.message);
            }
        }
        
        function viewDocs() {
            alert('API documentation will be available soon.\n\n' +
                  'For now, use the following endpoints:\n' +
                  '- /api/movies (GET) - List movies\n' +
                  '- /api/auth/login (POST) - User login\n' +
                  '- /api/payments/verify (POST) - Verify MPesa payment\n' +
                  '- /api/user/profile (GET) - User profile');
        }
        
        function testPayment() {
            alert('Payment test flow:\n\n' +
                  '1. Register/Login as user\n' +
                  '2. Browse movies\n' +
                  '3. Select a movie\n' +
                  '4. Click "Buy for KES 30"\n' +
                  '5. Enter phone number\n' +
                  '6. Make payment via M-Pesa\n' +
                  '7. Enter transaction code\n' +
                  '8. Get access to movie!');
        }
        
        // Auto-check on page load
        window.addEventListener('load', checkHealth);
    </script>
</body>
</html>''')
    
    # Start the Flask application
    port = int(os.getenv('PORT', 5000))
    debug_mode = not IS_PRODUCTION
    
    print(f"\n🚀 Starting server on port {port} (Debug: {debug_mode})")
    print("📱 Available on:")
    print(f"   • Web: http://localhost:{port}")
    print(f"   • Mobile: Capacitor/React Native compatible")
    print(f"   • Desktop: Electron/Tauri compatible")
    print("\n⚡ Press Ctrl+C to stop")
    print("="*70 + "\n")
    
    try:
        app.run(
            host='0.0.0.0',
            port=port,
            debug=debug_mode,
            threaded=True,
            use_reloader=debug_mode
        )
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server error: {str(e)}")
        sys.exit(1)
