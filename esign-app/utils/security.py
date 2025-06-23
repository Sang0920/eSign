import os
import time
import uuid
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from flask import session, current_app
import logging

logger = logging.getLogger(__name__)

class SecurePasswordManager:
    """Secure password management for PDF signing operations"""
    
    def __init__(self):
        self.timeout_seconds = 1800  # 30 minutes timeout (increased for production)
        
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
        try:
            salt = os.urandom(16)
            
            key = self._generate_key(str(user_id), salt)
            fernet = Fernet(key)
            
            encrypted_password = fernet.encrypt(password.encode())
            
            token = str(uuid.uuid4())  # Use UUID for better uniqueness
            
            session_data = {
                'encrypted_password': base64.b64encode(encrypted_password).decode(),
                'salt': base64.b64encode(salt).decode(),
                'timestamp': time.time(),
                'user_id': user_id,
                'version': 1  # Add version for future compatibility
            }
            
            session_key = f'secure_auth_{token}'
            session[session_key] = session_data
            
            session.permanent = True
            
            logger.info(f"Stored password session for user {user_id} with token {token[:8]}...")
            return token
            
        except Exception as e:
            logger.error(f"Failed to store password session: {e}")
            raise ValueError("Failed to create authentication session")
    
    def retrieve_password(self, token: str, user_id: int) -> str:
        """Retrieve and decrypt password if still valid"""
        try:
            session_key = f'secure_auth_{token}'
            
            if session_key not in session:
                logger.warning(f"Authentication session not found for token {token[:8]}... and user {user_id}")
                raise ValueError("Authentication session not found")
            
            session_data = session[session_key]
            
            current_time = time.time()
            if current_time - session_data['timestamp'] > self.timeout_seconds:
                self.clear_password_session(token)
                logger.warning(f"Authentication session expired for user {user_id}")
                raise ValueError("Authentication session expired")
            
            if session_data['user_id'] != user_id:
                logger.warning(f"Invalid user ID in session. Expected {user_id}, got {session_data['user_id']}")
                raise ValueError("Invalid authentication session")
            
            salt = base64.b64decode(session_data['salt'])
            key = self._generate_key(str(user_id), salt)
            fernet = Fernet(key)
            
            encrypted_password = base64.b64decode(session_data['encrypted_password'])
            password = fernet.decrypt(encrypted_password).decode()
            
            logger.info(f"Successfully retrieved password for user {user_id}")
            return password
            
        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Failed to retrieve password session: {e}")
            raise ValueError("Failed to retrieve authentication session")
    
    def clear_password_session(self, token: str = None):
        """Clear password session data"""
        try:
            if token:
                session_key = f'secure_auth_{token}'
                if session_key in session:
                    session.pop(session_key, None)
                    logger.info(f"Cleared specific password session for token {token[:8]}...")
            else:
                keys_to_remove = [key for key in session.keys() if key.startswith('secure_auth_')]
                for key in keys_to_remove:
                    session.pop(key, None)
                logger.info(f"Cleared {len(keys_to_remove)} password sessions")
        except Exception as e:
            logger.error(f"Failed to clear password sessions: {e}")
    
    def extend_session(self, token: str, user_id: int):
        """Extend session timeout for active use"""
        try:
            session_key = f'secure_auth_{token}'
            if session_key in session and session[session_key]['user_id'] == user_id:
                session[session_key]['timestamp'] = time.time()
                logger.debug(f"Extended session for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to extend session: {e}")

password_manager = SecurePasswordManager()
