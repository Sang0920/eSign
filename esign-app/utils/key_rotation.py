import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
import logging
from models import User, db
from utils.crypto import generate_key_pair

logger = logging.getLogger(__name__)

class KeyRotationManager:
    """
    Key rotation system for managing certificate and key lifecycle
    """
    
    def __init__(self, keys_folder: Path):
        self.keys_folder = Path(keys_folder)
        self.backup_folder = self.keys_folder / 'backups'
        self.backup_folder.mkdir(parents=True, exist_ok=True)
    
    def should_rotate_keys(self, user_id: int) -> dict:
        """
        Check if user's keys should be rotated based on various criteria
        
        Args:
            user_id: User ID to check
            
        Returns:
            Dictionary with rotation recommendation
        """
        user_keys_folder = self.keys_folder / str(user_id)
        cert_path = user_keys_folder / 'certificate.pem'
        
        rotation_reasons = []
        recommendations = []
        
        if not cert_path.exists():
            return {
                'should_rotate': True,
                'urgency': 'high',
                'reasons': ['No certificate found'],
                'recommendations': ['Generate new certificate immediately']
            }
        
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data)
            
            now = datetime.now(timezone.utc)
            
            try:
                not_valid_before = cert.not_valid_before_utc
                not_valid_after = cert.not_valid_after_utc
            except AttributeError:
                not_valid_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_valid_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
            
            cert_age = now - not_valid_before
            max_cert_age = timedelta(days=365)  # 1 year
            
            if cert_age > max_cert_age:
                rotation_reasons.append(f"Certificate is {cert_age.days} days old (max recommended: {max_cert_age.days})")
                recommendations.append("Rotate certificate due to age")
            
            days_until_expiry = (not_valid_after - now).days
            
            if days_until_expiry <= 0:
                rotation_reasons.append("Certificate has expired")
                recommendations.append("Immediate rotation required - certificate expired")
                urgency = 'critical'
            elif days_until_expiry <= 30:
                rotation_reasons.append(f"Certificate expires in {days_until_expiry} days")
                recommendations.append("Schedule rotation soon - certificate expiring")
                urgency = 'high'
            elif days_until_expiry <= 90:
                rotation_reasons.append(f"Certificate expires in {days_until_expiry} days")
                recommendations.append("Consider scheduling rotation - certificate expiring soon")
                urgency = 'medium'
            else:
                urgency = 'low'
            
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                key_size = public_key.key_size
                if key_size < 2048:
                    rotation_reasons.append(f"Key size ({key_size} bits) below recommended minimum (2048 bits)")
                    recommendations.append("Rotate to use stronger key size")
                    urgency = max(urgency, 'high') if urgency != 'critical' else urgency
            
            security_incident = self._check_security_incidents(user_id)
            if security_incident['incident_detected']:
                rotation_reasons.extend(security_incident['reasons'])
                recommendations.append("Rotate keys due to security incident")
                urgency = 'critical'
            
            should_rotate = len(rotation_reasons) > 0 or urgency in ['high', 'critical']
            
            return {
                'should_rotate': should_rotate,
                'urgency': urgency,
                'reasons': rotation_reasons,
                'recommendations': recommendations,
                'certificate_info': {
                    'expires': not_valid_after.isoformat(),
                    'days_until_expiry': days_until_expiry,
                    'key_size': getattr(public_key, 'key_size', 'unknown'),
                    'age_days': cert_age.days
                }
            }
            
        except Exception as e:
            logger.error(f"Error checking key rotation for user {user_id}: {e}")
            return {
                'should_rotate': True,
                'urgency': 'high',
                'reasons': [f"Error analyzing certificate: {str(e)}"],
                'recommendations': ['Investigate certificate issues and consider rotation']
            }
        
    def rotate_user_keys(self, user_id: int, old_password: str, new_password: str = None) -> dict:
        """
        Perform key rotation for a user
        
        Args:
            user_id: User ID
            old_password: Current password
            new_password: New password (if changing), uses old_password if None
            
        Returns:
            Dictionary with rotation results
        """
        if new_password is None:
            new_password = old_password
            
        user = User.query.get(user_id)
        if not user:
            return {
                'success': False,
                'error': 'User not found'
            }
        
        user_keys_folder = self.keys_folder / str(user_id)
        
        try:
            backup_result = self._backup_existing_keys(user_id)
            if not backup_result['success']:
                return backup_result
            
            old_key_path = user_keys_folder / 'private_key.pem'
            if old_key_path.exists():
                verification_result = self._verify_old_password(old_key_path, old_password)
                if not verification_result['success']:
                    return {
                        'success': False,
                        'error': 'Old password verification failed'
                    }
            
            new_keys_result = generate_key_pair(user, new_password, self.keys_folder)
            
            verification_result = self._verify_new_keys(user_id, new_password)
            if not verification_result['success']:
                self._rollback_rotation(user_id, backup_result['backup_path'])
                return {
                    'success': False,
                    'error': 'New key verification failed, rotation rolled back'
                }
            
            user.key_rotation_date = datetime.now(timezone.utc)
            db.session.commit()
            
            logger.info(f"Successfully rotated keys for user {user_id}")
            
            return {
                'success': True,
                'message': 'Keys rotated successfully',
                'backup_path': backup_result['backup_path'],
                'new_certificate_path': new_keys_result['certificate_path'],
                'rotation_date': user.key_rotation_date.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error during key rotation for user {user_id}: {e}")
            return {
                'success': False,
                'error': f'Key rotation failed: {str(e)}'
            }
    
    def _backup_existing_keys(self, user_id: int) -> dict:
        """Create backup of existing keys"""
        user_keys_folder = self.keys_folder / str(user_id)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = self.backup_folder / f"user_{user_id}_{timestamp}"
        
        try:
            if user_keys_folder.exists():
                shutil.copytree(user_keys_folder, backup_path)
                logger.info(f"Backed up keys for user {user_id} to {backup_path}")
                
            return {
                'success': True,
                'backup_path': backup_path
            }
            
        except Exception as e:
            logger.error(f"Failed to backup keys for user {user_id}: {e}")
            return {
                'success': False,
                'error': f'Backup failed: {str(e)}'
            }
    
    def _verify_old_password(self, key_path: Path, password: str) -> dict:
        """Verify old password works with existing private key"""
        try:
            with open(key_path, 'rb') as f:
                key_data = f.read()
            
            load_pem_private_key(key_data, password.encode('utf-8'))
            
            return {'success': True}
            
        except Exception as e:
            logger.error(f"Old password verification failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _verify_new_keys(self, user_id: int, password: str) -> dict:
        """Verify new keys are working properly"""
        user_keys_folder = self.keys_folder / str(user_id)
        key_path = user_keys_folder / 'private_key.pem'
        cert_path = user_keys_folder / 'certificate.pem'
        
        try:
            with open(key_path, 'rb') as f:
                key_data = f.read()
            private_key = load_pem_private_key(key_data, password.encode('utf-8'))
            
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)
            
            cert_public_key = cert.public_key()
            private_public_key = private_key.public_key()
            
            test_data = b"key_verification_test"
            from cryptography.hazmat.primitives.asymmetric import padding
            
            encrypted = cert_public_key.encrypt(
                test_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            decrypted = private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            if decrypted != test_data:
                return {
                    'success': False,
                    'error': 'Key and certificate do not match'
                }
            
            return {'success': True}
            
        except Exception as e:
            logger.error(f"New key verification failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _rollback_rotation(self, user_id: int, backup_path: Path):
        """Rollback key rotation by restoring from backup"""
        user_keys_folder = self.keys_folder / str(user_id)
        
        try:
            if user_keys_folder.exists():
                shutil.rmtree(user_keys_folder)
            
            shutil.copytree(backup_path, user_keys_folder)
            logger.info(f"Rolled back key rotation for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to rollback key rotation for user {user_id}: {e}")
    
    def _check_security_incidents(self, user_id: int) -> dict:
        """
        Check for security incidents that would require key rotation
        This is a placeholder - integrate with your security monitoring system
        """
        # Placeholder implementation
        return {
            'incident_detected': False,
            'reasons': []
        }
    
    def cleanup_old_backups(self, days_to_keep: int = 90):
        """Clean up old backup files"""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        deleted_count = 0
        for backup_dir in self.backup_folder.iterdir():
            if backup_dir.is_dir():
                try:
                    # Extract timestamp from directory name
                    timestamp_str = backup_dir.name.split('_')[-2] + '_' + backup_dir.name.split('_')[-1]
                    backup_date = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
                    
                    if backup_date < cutoff_date:
                        shutil.rmtree(backup_dir)
                        deleted_count += 1
                        logger.info(f"Deleted old backup: {backup_dir}")
                        
                except Exception as e:
                    logger.warning(f"Could not process backup directory {backup_dir}: {e}")
        
        logger.info(f"Cleaned up {deleted_count} old backup directories")
        return deleted_count

key_rotation_manager = KeyRotationManager(Path('keys'))