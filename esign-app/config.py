import os
from datetime import timedelta

class Config:
    # Flask Settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'sang0920-secret-key-for-development'
    
    # Database Settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///pdfsigner.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File Upload Settings
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    ALLOWED_EXTENSIONS = {'pdf'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload
    
    # Signature Settings
    SIGNATURE_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'signatures')
    
    # Keys Settings
    KEYS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')
    
    # Session Settings
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # Timestamp Authority
    TSA_URL = "http://timestamp.digicert.com"