import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from flask import session, current_app

class SecurePasswordManager:
    """Secure password management for PDF signing operations"""
    
    def __init__(self):
        self.timeout_seconds = 300  # 5 minutes timeout
        
    def _generate_key(self, password: str, salt: bytes) -> bytes:
        """Generate encryption key from password and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def store_password_temporarily(self, password: str, user_id: int) -> str:
        """Store password temporarily with encryption and timeout"""
        salt = os.urandom(16)
        
        key = self._generate_key(str(user_id), salt)
        fernet = Fernet(key)
        
        encrypted_password = fernet.encrypt(password.encode())
        
        session_data = {
            'encrypted_password': base64.b64encode(encrypted_password).decode(),
            'salt': base64.b64encode(salt).decode(),
            'timestamp': time.time(),
            'user_id': user_id
        }
        
        token = base64.urlsafe_b64encode(os.urandom(32)).decode()
        session[f'secure_auth_{token}'] = session_data
        
        return token
    
    def retrieve_password(self, token: str, user_id: int) -> str:
        """Retrieve and decrypt password if still valid"""
        session_key = f'secure_auth_{token}'
        
        if session_key not in session:
            raise ValueError("Authentication session not found")
        
        session_data = session[session_key]
        
        if time.time() - session_data['timestamp'] > self.timeout_seconds:
            self.clear_password_session(token)
            raise ValueError("Authentication session expired")
        
        if session_data['user_id'] != user_id:
            raise ValueError("Invalid authentication session")
        
        salt = base64.b64decode(session_data['salt'])
        key = self._generate_key(str(user_id), salt)
        fernet = Fernet(key)
        
        encrypted_password = base64.b64decode(session_data['encrypted_password'])
        password = fernet.decrypt(encrypted_password).decode()
        
        return password
    
    def clear_password_session(self, token: str = None):
        """Clear password session data"""
        if token:
            session_key = f'secure_auth_{token}'
            session.pop(session_key, None)
        else:
            keys_to_remove = [key for key in session.keys() if key.startswith('secure_auth_')]
            for key in keys_to_remove:
                session.pop(key, None)
    
    def extend_session(self, token: str, user_id: int):
        """Extend session timeout for active use"""
        session_key = f'secure_auth_{token}'
        if session_key in session and session[session_key]['user_id'] == user_id:
            session[session_key]['timestamp'] = time.time()

password_manager = SecurePasswordManager()