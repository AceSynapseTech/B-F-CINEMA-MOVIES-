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

# =========== MPESA CONFIGURATION ===========
MPESA_CONFIG = {
    'consumer_key': os.getenv('MPESA_CONSUMER_KEY', 'f40fc85618'),
    'consumer_secret': os.getenv('MPESA_CONSUMER_SECRET', '7f6c65d70a80c58a7e2e3bf1889305d9'),
    'business_shortcode': os.getenv('MPESA_BUSINESS_SHORTCODE', '7048202'),
    'passkey': os.getenv('MPESA_PASSKEY', 'bf62b5a5f0ec05ff7bda0a21d146ef9e6d0f5cd2f38e6'),
    'environment': os.getenv('MPESA_ENVIRONMENT', 'sandbox'),  # sandbox or production
    'callback_url': os.getenv('MPESA_CALLBACK_URL', 'https://b-f-cinema-movies-mj6b.onrender.com/api/mpesa-callback'),
    'account_reference': os.getenv('MPESA_ACCOUNT_REFERENCE', 'B/F Cinema Movies'),
    'transaction_desc': os.getenv('MPESA_TRANSACTION_DESC', 'Movie Purchase')
}

# MPesa API endpoints
MPESA_API_URLS = {
    'sandbox': {
        'auth': 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
        'stk_push': 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
    },
    'production': {
        'auth': 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
        'stk_push': 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
    }
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
                stream_url TEXT,
                price DECIMAL(10,2) DEFAULT 30.00,
                payment_link TEXT
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
                mpesa_checkout_request_id TEXT,
                mpesa_merchant_request_id TEXT,
                mpesa_result_code TEXT,
                mpesa_result_desc TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (movie_id) REFERENCES movies(id) ON DELETE CASCADE
            )
        """)
        
        # MPesa STK Push table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mpesa_stk_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkout_request_id TEXT UNIQUE NOT NULL,
                merchant_request_id TEXT,
                user_id INTEGER NOT NULL,
                movie_id INTEGER NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                phone_number TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                result_code TEXT,
                result_desc TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_mpesa_checkout_id ON mpesa_stk_requests(checkout_request_id)')
        
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
    """Get database connection"""
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

# =========== INITIALIZE ON STARTUP ===========
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
print(f"💰 MPesa Integration: {'✅ Configured' if MPESA_CONFIG['consumer_key'] else '❌ Not Configured'}")
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

# =========== MPESA HELPER FUNCTIONS ===========
def get_mpesa_access_token():
    """Get MPesa OAuth access token"""
    try:
        consumer_key = MPESA_CONFIG['consumer_key']
        consumer_secret = MPESA_CONFIG['consumer_secret']
        environment = MPESA_CONFIG['environment']
        
        credentials = f"{consumer_key}:{consumer_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        auth_url = MPESA_API_URLS[environment]['auth']
        
        headers = {
            'Authorization': f'Basic {encoded_credentials}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(auth_url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            access_token = data.get('access_token')
            logger.info(f"✅ MPesa access token obtained")
            return access_token
        else:
            logger.error(f"❌ MPesa token error: {response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"❌ MPesa token error: {str(e)}")
        return None

def generate_mpesa_password(timestamp):
    """Generate MPesa API password"""
    business_shortcode = MPESA_CONFIG['business_shortcode']
    passkey = MPESA_CONFIG['passkey']
    
    data_to_encode = f"{business_shortcode}{passkey}{timestamp}"
    encoded_password = base64.b64encode(data_to_encode.encode()).decode()
    
    return encoded_password

def initiate_stk_push(phone_number, amount, movie_id, user_id):
    """Initiate MPesa STK Push payment"""
    try:
        access_token = get_mpesa_access_token()
        if not access_token:
            return {'success': False, 'error': 'Failed to get MPesa access token'}
        
        # Format phone number
        if phone_number.startswith('0'):
            phone_number = '254' + phone_number[1:]
        elif phone_number.startswith('+254'):
            phone_number = phone_number[1:]
        
        if not phone_number.startswith('254'):
            return {'success': False, 'error': 'Invalid phone number format'}
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        password = generate_mpesa_password(timestamp)
        
        request_data = {
            "BusinessShortCode": MPESA_CONFIG['business_shortcode'],
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": str(int(amount)),
            "PartyA": phone_number,
            "PartyB": MPESA_CONFIG['business_shortcode'],
            "PhoneNumber": phone_number,
            "CallBackURL": MPESA_CONFIG['callback_url'],
            "AccountReference": MPESA_CONFIG['account_reference'],
            "TransactionDesc": f"{MPESA_CONFIG['transaction_desc']} - Movie ID: {movie_id}"
        }
        
        environment = MPESA_CONFIG['environment']
        stk_push_url = MPESA_API_URLS[environment]['stk_push']
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(stk_push_url, json=request_data, headers=headers, timeout=30)
        
        if response.status_code == 200:
            response_data = response.json()
            
            if response_data.get('ResponseCode') == '0':
                checkout_request_id = response_data.get('CheckoutRequestID')
                merchant_request_id = response_data.get('MerchantRequestID')
                
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO mpesa_stk_requests 
                    (checkout_request_id, merchant_request_id, user_id, movie_id, amount, phone_number, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'pending')
                ''', (checkout_request_id, merchant_request_id, user_id, movie_id, amount, phone_number))
                conn.commit()
                conn.close()
                
                return {
                    'success': True,
                    'message': 'Please check your phone to complete payment',
                    'checkout_request_id': checkout_request_id
                }
            else:
                return {'success': False, 'error': response_data.get('ResponseDescription', 'Payment failed')}
        else:
            return {'success': False, 'error': f'Payment initiation failed'}
            
    except Exception as e:
        logger.error(f"❌ STK Push error: {str(e)}")
        return {'success': False, 'error': str(e)}

def process_mpesa_callback(callback_data):
    """Process MPesa callback data"""
    try:
        result_code = callback_data.get('Body', {}).get('stkCallback', {}).get('ResultCode')
        result_desc = callback_data.get('Body', {}).get('stkCallback', {}).get('ResultDesc')
        checkout_request_id = callback_data.get('Body', {}).get('stkCallback', {}).get('CheckoutRequestID')
        
        if not checkout_request_id:
            return {'success': False, 'error': 'No checkout request ID'}
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM mpesa_stk_requests WHERE checkout_request_id = ?', (checkout_request_id,))
        stk_request = cursor.fetchone()
        
        if not stk_request:
            return {'success': False, 'error': 'STK request not found'}
        
        stk_request_dict = row_to_dict(stk_request)
        
        cursor.execute('''
            UPDATE mpesa_stk_requests 
            SET status = ?, result_code = ?, result_desc = ?, updated_at = CURRENT_TIMESTAMP
            WHERE checkout_request_id = ?
        ''', ('completed', result_code, result_desc, checkout_request_id))
        
        if result_code == '0':
            callback_metadata = callback_data.get('Body', {}).get('stkCallback', {}).get('CallbackMetadata', {}).get('Item', [])
            
            transaction_details = {}
            for item in callback_metadata:
                transaction_details[item.get('Name')] = item.get('Value')
            
            amount = transaction_details.get('Amount')
            mpesa_receipt_number = transaction_details.get('MpesaReceiptNumber')
            phone_number = transaction_details.get('PhoneNumber')
            
            cursor.execute('SELECT * FROM movies WHERE id = ?', (stk_request_dict['movie_id'],))
            movie = cursor.fetchone()
            
            if movie:
                movie_dict = row_to_dict(movie)
                
                cursor.execute('''
                    INSERT INTO transactions 
                    (transaction_code, user_id, user_email, user_phone, movie_id, movie_title, 
                     mpesa_message, amount, payment_date, payment_time, status, verified_at,
                     mpesa_checkout_request_id, mpesa_merchant_request_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', CURRENT_TIMESTAMP, ?, ?)
                ''', (
                    mpesa_receipt_number, stk_request_dict['user_id'], '', 
                    phone_number or stk_request_dict['phone_number'],
                    stk_request_dict['movie_id'], movie_dict['title'],
                    f'MPesa Payment - {mpesa_receipt_number}',
                    amount or stk_request_dict['amount'],
                    datetime.now().strftime('%d/%m/%y'),
                    datetime.now().strftime('%I:%M %p'),
                    checkout_request_id, stk_request_dict['merchant_request_id']
                ))
                
                transaction_id = cursor.lastrowid
                
                cursor.execute('SELECT email FROM users WHERE id = ?', (stk_request_dict['user_id'],))
                user = cursor.fetchone()
                user_email = user['email'] if user else ''
                cursor.execute('UPDATE transactions SET user_email = ? WHERE id = ?', (user_email, transaction_id))
                
                cursor.execute('''
                    INSERT OR REPLACE INTO user_access (user_id, movie_id, transaction_id, is_active)
                    VALUES (?, ?, ?, 1)
                ''', (stk_request_dict['user_id'], stk_request_dict['movie_id'], transaction_id))
                
                # Generate video URL
                video_url = generate_presigned_url(movie_dict.get('video_key'))
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
                ''', (stk_request_dict['user_id'], stk_request_dict['movie_id'], movie_data))
                
                cursor.execute('UPDATE movies SET download_count = download_count + 1 WHERE id = ?', (stk_request_dict['movie_id'],))
                cursor.execute('UPDATE users SET downloads = downloads + 1 WHERE id = ?', (stk_request_dict['user_id'],))
                
                conn.commit()
                
                log_activity(stk_request_dict['user_id'], user_email, 'mpesa_payment_success', {
                    'movie_id': stk_request_dict['movie_id'],
                    'transaction_code': mpesa_receipt_number
                })
                
                return {'success': True, 'message': 'Payment successful', 'transaction_code': mpesa_receipt_number}
            else:
                return {'success': False, 'error': 'Movie not found'}
        else:
            log_activity(stk_request_dict['user_id'], '', 'mpesa_payment_failed', {
                'movie_id': stk_request_dict['movie_id'],
                'error': result_desc
            })
            return {'success': False, 'error': result_desc}
            
    except Exception as e:
        logger.error(f"❌ MPesa callback error: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        if conn:
            conn.close()

def check_payment_status(checkout_request_id):
    """Check payment status"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM mpesa_stk_requests WHERE checkout_request_id = ?', (checkout_request_id,))
        stk_request = cursor.fetchone()
        
        if not stk_request:
            return {'success': False, 'error': 'Payment request not found'}
        
        stk_request_dict = row_to_dict(stk_request)
        
        cursor.execute('SELECT * FROM transactions WHERE mpesa_checkout_request_id = ?', (checkout_request_id,))
        transaction = cursor.fetchone()
        
        conn.close()
        
        if transaction:
            return {'success': True, 'status': 'completed', 'transaction': row_to_dict(transaction)}
        else:
            return {'success': True, 'status': stk_request_dict['status']}
            
    except Exception as e:
        logger.error(f"❌ Payment status error: {str(e)}")
        return {'success': False, 'error': str(e)}

# =========== HELPER FUNCTIONS ===========
def generate_presigned_url(key, expires=7200):
    """Generate presigned URL for video streaming"""
    if not s3_client or not key:
        return None
    
    try:
        content_type = 'video/mp4'
        key_lower = key.lower()
        if key_lower.endswith(('.jpg', '.jpeg')):
            content_type = 'image/jpeg'
        elif key_lower.endswith('.png'):
            content_type = 'image/png'
        
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': BACKBLAZE_CONFIG['bucket'],
                'Key': key,
                'ResponseContentType': content_type,
                'ResponseContentDisposition': 'inline'
            },
            ExpiresIn=expires,
            HttpMethod='GET'
        )
        return url
    except Exception as e:
        logger.error(f"❌ Presigned URL error: {str(e)}")
        return None

def log_activity(user_id, user_email, action, details=None):
    """Log user activity"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        details_str = json.dumps(details) if details else '{}'
        cursor.execute('''
            INSERT INTO activity_log (user_id, user_email, action, details)
            VALUES (?, ?, ?, ?)
        ''', (str(user_id), user_email, action, details_str))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Activity log error: {str(e)}")

# =========== AUTO-DELETION FUNCTIONS ===========
def calculate_expiry_date():
    """Calculate expiry date 10 months from now"""
    return datetime.now() + timedelta(days=300)

def delete_expired_movies():
    """Delete movies that have passed their expiry date"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        now = datetime.now()
        
        cursor.execute('''
            SELECT id, title, video_key, poster_key 
            FROM movies 
            WHERE expires_at IS NOT NULL AND expires_at < ? AND is_active = 1
        ''', (now,))
        
        expired_movies = cursor.fetchall()
        
        for movie in expired_movies:
            movie_dict = row_to_dict(movie)
            if s3_client and movie_dict['video_key']:
                try:
                    s3_client.delete_object(Bucket=BACKBLAZE_CONFIG['bucket'], Key=movie_dict['video_key'])
                    if movie_dict.get('poster_key'):
                        s3_client.delete_object(Bucket=BACKBLAZE_CONFIG['bucket'], Key=movie_dict['poster_key'])
                except Exception as e:
                    logger.error(f"Failed to delete from B2: {str(e)}")
            
            cursor.execute('UPDATE movies SET is_active = 0 WHERE id = ?', (movie_dict['id'],))
        
        conn.commit()
        conn.close()
        return len(expired_movies)
    except Exception as e:
        logger.error(f"Error deleting expired movies: {str(e)}")
        return 0

def schedule_auto_deletion():
    """Schedule automatic deletion"""
    try:
        schedule.every().day.at("02:00").do(delete_expired_movies)
        
        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(60)
        
        threading.Thread(target=run_scheduler, daemon=True).start()
    except Exception as e:
        logger.error(f"Scheduler error: {str(e)}")

# =========== ACCESS CONTROL FUNCTIONS ===========
def has_movie_access(user_id, movie_id):
    """Check if user has access to a movie"""
    if not user_id or user_id == 'admin_001':
        return user_id == 'admin_001'
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM user_access WHERE user_id = ? AND movie_id = ? AND is_active = 1', (user_id, movie_id))
        has_access = cursor.fetchone() is not None
        conn.close()
        return has_access
    except Exception as e:
        logger.error(f"Access check error: {str(e)}")
        return False

# =========== CORS MIDDLEWARE ===========
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin', '')
    if origin in allowed_origins:
        response.headers.add('Access-Control-Allow-Origin', origin)
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Range,X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS,PATCH')
    response.headers.add('Accept-Ranges', 'bytes')
    return response

@app.before_request
def before_request():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        origin = request.headers.get('Origin', '')
        if origin in allowed_origins:
            response.headers.add('Access-Control-Allow-Origin', origin)
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Range,X-Requested-With')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS,PATCH')
        return response, 200

# =========== MPESA PAYMENT ENDPOINTS ===========
@app.route('/api/movies/<int:movie_id>/initiate-payment', methods=['POST'])
def initiate_payment(movie_id):
    """Initiate MPesa payment for a movie"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        data = request.get_json()
        phone_number = data.get('phone_number', '').strip()
        
        if not phone_number:
            return jsonify({'success': False, 'error': 'Phone number is required'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM movies WHERE id = ?', (movie_id,))
        movie = cursor.fetchone()
        conn.close()
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        movie_dict = row_to_dict(movie)
        amount = float(movie_dict.get('price', 30.00))
        
        if has_movie_access(session['user_id'], movie_id):
            return jsonify({'success': False, 'error': 'You already have access to this movie'}), 400
        
        result = initiate_stk_push(phone_number, amount, movie_id, session['user_id'])
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': result['message'],
                'checkout_request_id': result['checkout_request_id'],
                'movie_title': movie_dict['title'],
                'amount': amount
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Payment failed')}), 400
            
    except Exception as e:
        logger.error(f"Payment error: {str(e)}")
        return jsonify({'success': False, 'error': 'Payment failed'}), 500

@app.route('/api/movies/<int:movie_id>/check-payment-status', methods=['GET'])
def check_payment_status_endpoint(movie_id):
    """Check payment status"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        checkout_request_id = request.args.get('checkout_request_id')
        
        if not checkout_request_id:
            return jsonify({'success': False, 'error': 'Checkout request ID required'}), 400
        
        result = check_payment_status(checkout_request_id)
        
        if not result['success']:
            return jsonify({'success': False, 'error': result['error']}), 400
        
        has_access = has_movie_access(session['user_id'], movie_id)
        
        return jsonify({
            'success': True,
            'status': result['status'],
            'has_access': has_access,
            'transaction_code': result.get('transaction', {}).get('transaction_code') if result['status'] == 'completed' else None
        })
        
    except Exception as e:
        logger.error(f"Status check error: {str(e)}")
        return jsonify({'success': False, 'error': 'Status check failed'}), 500

@app.route('/api/mpesa-callback', methods=['POST'])
def mpesa_callback():
    """Handle MPesa callback"""
    try:
        callback_data = request.get_json()
        
        if not callback_data:
            return jsonify({'ResultCode': 1, 'ResultDesc': 'Invalid data'}), 400
        
        result = process_mpesa_callback(callback_data)
        
        if result['success']:
            return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        else:
            return jsonify({'ResultCode': 1, 'ResultDesc': result.get('error', 'Failed')})
            
    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Error'}), 500

# =========== UPLOAD ENDPOINTS ===========
@app.route('/api/upload-file', methods=['POST'])
def upload_file():
    """Upload file endpoint"""
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
        unique_id = str(uuid.uuid4())[:8]
        extension = os.path.splitext(file.filename)[1] or ('.jpg' if file_type == 'poster' else '.mp4')
        filename = f"{unique_id}_{file_type}{extension}"
        filepath = os.path.join(temp_dir, filename)
        
        file.save(filepath)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'filepath': filepath,
            'file_type': file_type,
            'size': os.path.getsize(filepath)
        })
        
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/upload-movie-complete', methods=['POST'])
def upload_movie_complete():
    """Complete movie upload"""
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
            return jsonify({'success': False, 'error': 'Title required'}), 400
        
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
            with open(video_path, 'rb') as f:
                s3_client.upload_fileobj(f, BACKBLAZE_CONFIG['bucket'], video_key, ExtraArgs={'ContentType': 'video/mp4'})
            video_url = generate_presigned_url(video_key)
        
        poster_key = None
        if poster_path and os.path.exists(poster_path):
            poster_ext = os.path.splitext(poster_filename)[1].lower() or '.jpg'
            poster_key = f"posters/{unique_id}_{safe_title}{poster_ext}"
            if s3_client:
                with open(poster_path, 'rb') as f:
                    s3_client.upload_fileobj(f, BACKBLAZE_CONFIG['bucket'], poster_key, ExtraArgs={'ContentType': 'image/jpeg'})
        
        expiry_date = calculate_expiry_date()
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO movies (title, description, year, duration, video_key, poster_key,
                uploaded_by, uploaded_at, expires_at, file_size, file_type, price)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, 'video/mp4', 30.00)
        """, (title, description, year, duration, video_key, poster_key, session.get('name', 'Admin'), expiry_date, os.path.getsize(video_path)))
        
        movie_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Cleanup temp files
        try:
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
            'expires_at': expiry_date.isoformat()
        })
        
    except Exception as e:
        logger.error(f"Complete upload error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# =========== VIDEO STREAMING ENDPOINTS ===========
@app.route('/api/stream-video/<int:movie_id>', methods=['GET'])
def stream_video_direct(movie_id):
    """Get streaming URL for movie"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        if not has_movie_access(session['user_id'], movie_id):
            return jsonify({'success': False, 'error': 'Access denied. Purchase required.'}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT video_key, title, is_active FROM movies WHERE id = ?', (movie_id,))
        movie = cursor.fetchone()
        conn.close()
        
        if not movie:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        movie_dict = row_to_dict(movie)
        
        if not movie_dict.get('is_active', 1):
            return jsonify({'success': False, 'error': 'Movie has expired'}), 410
        
        video_url = generate_presigned_url(movie_dict['video_key'])
        if not video_url:
            video_url = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
        
        return jsonify({
            'success': True,
            'video_url': video_url,
            'movie_title': movie_dict['title']
        })
        
    except Exception as e:
        logger.error(f"Stream error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

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
            conn.close()
            if movie:
                movie_id_int = movie['id']
            else:
                return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        if not has_movie_access(session['user_id'], movie_id_int):
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT video_key FROM movies WHERE id = ?', (movie_id_int,))
        movie = cursor.fetchone()
        conn.close()
        
        if not movie or not movie['video_key']:
            return jsonify({'success': False, 'error': 'Movie not found'}), 404
        
        video_url = generate_presigned_url(movie['video_key'])
        if not video_url:
            video_url = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
        
        return redirect(video_url, code=302)
            
    except Exception as e:
        logger.error(f"Stream proxy error: {str(e)}")
        return jsonify({'success': False, 'error': 'Streaming failed'}), 500

# =========== AUTHENTICATION ENDPOINTS ===========
@app.route('/api/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
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
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['name'] = user['name']
            session['email'] = user['email']
            session['is_admin'] = bool(user['is_admin'])
            session.permanent = True
            
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
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'error': 'Login failed'}), 500

@app.route('/save-user', methods=['POST'])
def save_user():
    """User registration endpoint"""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        phone = data.get('phone', '').strip()
        password = data.get('password', '')
        
        if not name or not email or not password:
            return jsonify({'success': False, 'error': 'Name, email, and password required'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = ? COLLATE NOCASE', (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        password_hash = generate_password_hash(password)
        cursor.execute('INSERT INTO users (name, email, phone, password_hash) VALUES (?, ?, ?, ?)', 
                      (name, email, phone, password_hash))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        log_activity(user_id, email, 'user_registration', {'name': name})
        
        return jsonify({
            'success': True,
            'message': 'Account created successfully',
            'user': {'id': user_id, 'name': name, 'email': email, 'phone': phone}
        })
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'success': False, 'error': 'Registration failed'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout endpoint"""
    try:
        user_id = session.get('user_id')
        user_email = session.get('email')
        if user_id:
            log_activity(user_id, user_email, 'logout')
        session.clear()
        return jsonify({'success': True, 'message': 'Logged out'})
    except Exception as e:
        return jsonify({'success': False, 'error': 'Logout failed'}), 500

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    """Check authentication status"""
    try:
        if 'user_id' in session:
            if session['user_id'] == 'admin_001':
                return jsonify({
                    'authenticated': True,
                    'user': {'id': 'admin_001', 'name': 'Administrator', 'email': 'BFCM2026@GMAIL.COM', 'isAdmin': True}
                })
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
            user = cursor.fetchone()
            conn.close()
            
            if user:
                return jsonify({
                    'authenticated': True,
                    'user': {'id': user['id'], 'name': user['name'], 'email': user['email'], 'isAdmin': bool(user['is_admin'])}
                })
        
        return jsonify({'authenticated': False})
    except Exception as e:
        return jsonify({'authenticated': False})

# =========== MOVIE ENDPOINTS ===========
@app.route('/api/movies', methods=['GET'])
def get_movies():
    """Get all movies"""
    try:
        user_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM movies WHERE is_active=1 ORDER BY uploaded_at DESC")
        rows = cursor.fetchall()
        conn.close()

        results = []
        for row in rows:
            movie = row_to_dict(row)
            
            video_url = generate_presigned_url(movie.get('video_key'))
            poster_url = generate_presigned_url(movie.get('poster_key'))
            
            if not video_url:
                video_url = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4"
            if not poster_url:
                poster_url = "https://images.unsplash.com/photo-1536440136628-849c177e76a1?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&q=80"
            
            has_access = has_movie_access(user_id, movie['id'])
            
            days_remaining = None
            if movie.get('expires_at'):
                expiry_date = datetime.fromisoformat(movie['expires_at'])
                days_remaining = (expiry_date - datetime.now()).days
            
            results.append({
                'id': movie['id'],
                'title': movie['title'],
                'description': movie.get('description', ''),
                'year': movie.get('year'),
                'duration': movie.get('duration'),
                'url': video_url,
                'poster': poster_url,
                'views': movie.get('views', 0),
                'downloads': movie.get('download_count', 0),
                'has_access': has_access,
                'days_remaining': days_remaining,
                'price': float(movie.get('price', 30.00))
            })

        return jsonify(success=True, movies=results)
    except Exception as e:
        logger.error(f"Get movies error: {str(e)}")
        return jsonify(success=False, error="Failed to load movies"), 500

@app.route('/api/movies/<int:movie_id>', methods=['GET'])
def get_movie_details(movie_id):
    """Get movie details"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM movies WHERE id=?", (movie_id,))
        movie = cursor.fetchone()
        conn.close()

        if not movie:
            return jsonify(success=False, error="Movie not found"), 404
        
        movie_dict = row_to_dict(movie)
        
        video_url = generate_presigned_url(movie_dict['video_key'])
        poster_url = generate_presigned_url(movie_dict.get('poster_key'))
        
        user_id = session.get('user_id')
        has_access = has_movie_access(user_id, movie_id)
        
        return jsonify(success=True, movie={
            'id': movie_dict['id'],
            'title': movie_dict['title'],
            'description': movie_dict.get('description', ''),
            'year': movie_dict.get('year'),
            'duration': movie_dict.get('duration'),
            'url': video_url,
            'poster': poster_url,
            'views': movie_dict.get('views', 0),
            'downloads': movie_dict.get('download_count', 0),
            'has_access': has_access,
            'price': float(movie_dict.get('price', 30.00))
        })
    except Exception as e:
        logger.error(f"Get movie error: {str(e)}")
        return jsonify(success=False, error="Failed to load movie"), 500

@app.route('/api/movies/<int:movie_id>/check-access', methods=['GET'])
def check_movie_access(movie_id):
    """Check if user has access to movie"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'has_access': False, 'error': 'Authentication required'}), 401
        
        has_access = has_movie_access(session['user_id'], movie_id)
        return jsonify({'success': True, 'has_access': has_access})
    except Exception as e:
        return jsonify({'success': False, 'has_access': False}), 500

# =========== USER PROFILE ENDPOINTS ===========
@app.route('/api/user/downloads', methods=['GET'])
def get_user_downloads():
    """Get user's purchased movies"""
    try:
        if 'user_id' not in session or session['user_id'] == 'admin_001':
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT m.*, ua.access_granted_at as purchased_at
            FROM movies m
            JOIN user_access ua ON m.id = ua.movie_id
            WHERE ua.user_id = ? AND ua.is_active = 1 AND m.is_active = 1
            ORDER BY ua.access_granted_at DESC
        ''', (session['user_id'],))
        
        rows = cursor.fetchall()
        conn.close()
        
        downloads = []
        for row in rows:
            movie = row_to_dict(row)
            video_url = generate_presigned_url(movie.get('video_key'))
            poster_url = generate_presigned_url(movie.get('poster_key'))
            
            downloads.append({
                'movieId': movie['id'],
                'downloadedAt': movie.get('purchased_at'),
                'movieData': {
                    'id': movie['id'],
                    'title': movie['title'],
                    'poster': poster_url,
                    'year': movie.get('year'),
                    'duration': movie.get('duration'),
                    'url': video_url,
                    'description': movie.get('description', '')
                }
            })
        
        return jsonify({'success': True, 'downloads': downloads})
    except Exception as e:
        logger.error(f"Get downloads error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load downloads'}), 500

@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    """Get user profile"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        if session['user_id'] == 'admin_001':
            return jsonify({
                'success': True,
                'user': {
                    'id': 'admin_001',
                    'name': 'Administrator',
                    'email': 'BFCM2026@GMAIL.COM',
                    'phone': '+254 700 505325',
                    'isAdmin': True
                }
            })
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
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
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# =========== ADMIN ENDPOINTS ===========
@app.route('/api/admin/movies', methods=['GET'])
def get_admin_movies():
    """Get all movies for admin"""
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM movies ORDER BY uploaded_at DESC')
        rows = cursor.fetchall()
        conn.close()
        
        movies = []
        for row in rows:
            movie = row_to_dict(row)
            movies.append({
                'id': movie['id'],
                'title': movie['title'],
                'description': movie.get('description', ''),
                'year': movie.get('year'),
                'duration': movie.get('duration'),
                'views': movie.get('views', 0),
                'downloads': movie.get('download_count', 0),
                'uploaded_at': movie.get('uploaded_at'),
                'expires_at': movie.get('expires_at'),
                'is_active': bool(movie.get('is_active', 1)),
                'price': float(movie.get('price', 30.00))
            })
        
        return jsonify({'success': True, 'movies': movies})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/movies/<int:movie_id>', methods=['DELETE'])
def delete_movie(movie_id):
    """Delete movie"""
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
                logger.warning(f"Failed to delete from B2: {str(e)}")
        
        cursor.execute('DELETE FROM movies WHERE id = ?', (movie_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Movie deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/stats', methods=['GET'])
def get_admin_stats():
    """Get admin statistics"""
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
        
        cursor.execute('SELECT SUM(amount) FROM transactions WHERE status = "verified"')
        total_revenue = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_movies': total_movies,
                'total_users': total_users,
                'total_downloads': total_downloads,
                'total_revenue': float(total_revenue)
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/transactions', methods=['GET'])
def get_all_transactions():
    """Get all transactions for admin"""
    try:
        if not session.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT t.*, u.name as user_name, u.email
            FROM transactions t
            JOIN users u ON t.user_id = u.id
            ORDER BY t.created_at DESC
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        transactions = []
        for row in rows:
            trans = row_to_dict(row)
            transactions.append({
                'id': trans['id'],
                'transaction_code': trans['transaction_code'],
                'user_name': trans['user_name'],
                'user_email': trans['email'],
                'movie_title': trans['movie_title'],
                'amount': trans['amount'],
                'payment_date': trans['payment_date'],
                'payment_time': trans['payment_time'],
                'status': trans['status'],
                'created_at': trans['created_at']
            })
        
        return jsonify({'success': True, 'transactions': transactions})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# =========== HEALTH CHECK ===========
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'B/F Cinema Streaming Platform',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected',
        'backblaze_connected': s3_client is not None,
        'mpesa_configured': bool(MPESA_CONFIG['consumer_key']),
        'version': '2.1.0'
    })

# =========== STATIC FILE SERVING ===========
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

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

# =========== APPLICATION START ===========
if __name__ == '__main__':
    print("\n" + "="*60)
    print("🎬 B/F Cinema Streaming Platform - Version 2.1")
    print("="*60)
    print(f"📁 Environment: {'PRODUCTION' if RENDER else 'DEVELOPMENT'}")
    print(f"📁 Database: {get_db_path()}")
    print(f"☁️  Backblaze B2: {'✅ Connected' if s3_client else '❌ Not Connected'}")
    print(f"💰 MPesa Integration: {'✅ Configured' if MPESA_CONFIG['consumer_key'] else '❌ Not Configured'}")
    print(f"🗑️  Auto-deletion: ✅ Enabled (10 months expiry)")
    print("="*60)
    
    # Start auto-deletion scheduler
    try:
        schedule_auto_deletion()
        print("✅ Auto-deletion scheduler started")
    except Exception as e:
        print(f"⚠️  Could not start scheduler: {str(e)}")
    
    print("\n🚀 Starting server...")
    
    if RENDER:
        print("🌐 Production server on Render")
        print("📋 Admin Login:")
        print("   Email: BFCM2026@GMAIL.COM")
        print("   Password: [Set in Render environment variables]")
    else:
        print("🌐 Development server: http://localhost:5000")
        print("📋 Admin Login:")
        print("   Email: BFCM2026@GMAIL.COM")
        print("   Password: ASGWG2@##...")
    
    print("\n⚡ Press Ctrl+C to stop")
    print("="*60 + "\n")
    
    try:
        port = int(os.getenv('PORT', 5000))
        app.run(host='0.0.0.0', port=port, debug=not RENDER, threaded=True)
    except KeyboardInterrupt:
        print("\n👋 Server stopped")
