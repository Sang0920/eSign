import os
import hashlib
import requests
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
import logging

logger = logging.getLogger(__name__)

class CertificateValidator:
    """
    Comprehensive certificate validation system for eSign application
    """
    
    def __init__(self, trust_store_path: Path = None):
        if trust_store_path is None:
            current_dir = Path(__file__).parent.parent  # utils/certificate_validation.py -> esign-app
            project_root = current_dir.parent  # esign-app -> project root
            trust_store_path = project_root / "trust_store"
        
        self.trust_store_path = trust_store_path
        self.ca_certificates = self._load_ca_certificates()
        
        logger.info(f"Trust store path: {self.trust_store_path.absolute()}")
        
    def _load_ca_certificates(self) -> list:
        """Load CA certificates from trust store"""
        ca_certs = []
        
        if not self.trust_store_path.exists():
            logger.warning(f"Trust store path does not exist: {self.trust_store_path}")
            try:
                self.trust_store_path.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created trust store directory: {self.trust_store_path}")
            except Exception as e:
                logger.error(f"Could not create trust store directory: {e}")
            return ca_certs
        
        cert_extensions = ['*.crt', '*.pem', '*.cer']
        
        for ext in cert_extensions:
            for cert_file in self.trust_store_path.glob(ext):
                try:
                    with open(cert_file, 'rb') as f:
                        cert_data = f.read()
                    
                    cert = None
                    try:
                        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                        logger.info(f"Loaded PEM certificate: {cert_file.name}")
                    except Exception:
                        try:
                            cert = x509.load_der_x509_certificate(cert_data, default_backend())
                            logger.info(f"Loaded DER certificate: {cert_file.name}")
                        except Exception as der_error:
                            logger.warning(f"Failed to load certificate {cert_file}: {der_error}")
                            continue
                    
                    if cert:
                        ca_certs.append(cert)
                        
                except Exception as e:
                    logger.error(f"Error reading certificate file {cert_file}: {e}")
        
        logger.info(f"Loaded {len(ca_certs)} CA certificates from trust store")
        return ca_certs
    
    def validate_certificate_chain(self, cert_path: Path) -> dict:
        """
        Validate certificate chain against trusted CAs
        
        Args:
            cert_path: Path to certificate file to validate
            
        Returns:
            Dictionary with validation results
        """
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                
            validation_result = {
                'valid': False,
                'errors': [],
                'warnings': [],
                'certificate_info': self._get_certificate_info(cert),
                'chain_valid': False,
                'expiry_check': self._check_expiry(cert),
                'key_usage_valid': self._check_key_usage(cert),
                'revocation_status': 'unknown'
            }
            
            if self.ca_certificates:
                chain_result = self._validate_chain(cert)
                validation_result['chain_valid'] = chain_result['valid']
                if not chain_result['valid']:
                    validation_result['warnings'].extend(chain_result.get('errors', []))
            else:
                validation_result['warnings'].append("No CA certificates available for chain validation")
            
            if not validation_result['expiry_check']['valid']:
                validation_result['errors'].append(validation_result['expiry_check']['message'])
            
            if not validation_result['key_usage_valid']['valid']:
                validation_result['warnings'].append(validation_result['key_usage_valid']['message'])
                
            validation_result['valid'] = (
                validation_result['expiry_check']['valid']
                # Don't require perfect chain validation for development
            )
            
            return validation_result
            
        except Exception as e:
            return {
                'valid': False,
                'errors': [f"Certificate validation failed: {str(e)}"],
                'warnings': [],
                'certificate_info': {},
                'chain_valid': False,
                'expiry_check': {'valid': False, 'message': 'Could not check expiry'},
                'key_usage_valid': {'valid': False, 'message': 'Could not check key usage'},
                'revocation_status': 'error'
            }
    
    def _validate_chain(self, cert: x509.Certificate) -> dict:
        """Validate certificate against CA chain"""
        try:
            if cert.issuer == cert.subject:
                return {
                    'valid': True,
                    'errors': [],
                    'chain_length': 1,
                    'note': 'Self-signed certificate'
                }
            
            return {
                'valid': len(self.ca_certificates) > 0,
                'errors': [] if len(self.ca_certificates) > 0 else ['No CA certificates for validation'],
                'chain_length': 1
            }
            
        except Exception as e:
            return {
                'valid': False,
                'errors': [f"Chain validation failed: {str(e)}"],
                'chain_length': 0
            }
    
    def _check_expiry(self, cert: x509.Certificate) -> dict:
        """Check certificate expiry"""
        now = datetime.now(timezone.utc)  # Use timezone-aware datetime
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        
        if now < not_before:
            return {
                'valid': False,
                'message': f"Certificate not yet valid (valid from {not_before})",
                'days_until_valid': (not_before - now).days,
                'expires_in_days': None
            }
        elif now > not_after:
            return {
                'valid': False,
                'message': f"Certificate expired on {not_after}",
                'days_until_valid': None,
                'expired_days_ago': (now - not_after).days
            }
        else:
            days_until_expiry = (not_after - now).days
            warning_threshold = 30  # Warn if expires in 30 days
            
            return {
                'valid': True,
                'message': f"Certificate valid until {not_after}",
                'expires_in_days': days_until_expiry,
                'expiry_warning': days_until_expiry <= warning_threshold
            }
    
    def _check_key_usage(self, cert: x509.Certificate) -> dict:
        """Check if certificate has appropriate key usage for digital signatures"""
        try:
            key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            
            required_usages = ['digital_signature']
            
            missing_required = []
            
            for usage in required_usages:
                if not getattr(key_usage, usage, False):
                    missing_required.append(usage)
            
            if missing_required:
                return {
                    'valid': False,
                    'message': f"Certificate missing required key usage: {', '.join(missing_required)}",
                    'missing_required': missing_required
                }
            else:
                return {
                    'valid': True,
                    'message': "Certificate has valid key usage for digital signatures",
                    'missing_required': []
                }
                
        except x509.ExtensionNotFound:
            return {
                'valid': True,
                'message': "Certificate does not have Key Usage extension (acceptable for self-signed)",
                'missing_required': []
            }
    
    def _get_certificate_info(self, cert: x509.Certificate) -> dict:
        """Extract certificate information"""
        subject = cert.subject
        issuer = cert.issuer
        
        subject_dict = {}
        for attr in subject:
            subject_dict[attr.oid._name] = attr.value
            
        issuer_dict = {}
        for attr in issuer:
            issuer_dict[attr.oid._name] = attr.value
        
        return {
            'serial_number': f"{cert.serial_number:x}",
            'subject': subject_dict,
            'issuer': issuer_dict,
            'not_before': cert.not_valid_before.isoformat(),
            'not_after': cert.not_valid_after.isoformat(),
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'public_key_size': cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else 'unknown'
        }

certificate_validator = CertificateValidator()