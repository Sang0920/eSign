import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'sang0920-secret-key-for-development'
    
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///pdfsigner.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    ALLOWED_EXTENSIONS = {'pdf'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload
    
    SIGNATURE_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'signatures')
    KEYS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')
    
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)  # Increased from 7 days
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'  # HTTPS only in production
    SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
    
    if os.environ.get('FLASK_ENV') == 'production':
        SESSION_COOKIE_DOMAIN = '.onrender.com'  # Set your domain
        WTF_CSRF_TIME_LIMIT = 3600  # 1 hour CSRF token lifetime
    
    TSA_URL = "http://timestamp.digicert.com"
    DOCUMENTS_PER_PAGE = 10
    SIGNATURES_PER_PAGE = 12