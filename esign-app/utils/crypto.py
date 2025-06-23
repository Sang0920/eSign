import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import datetime
from pathlib import Path

def generate_key_pair(user, password, keys_folder):
    """Generate RSA key pair and self-signed certificate for a user"""
    user_keys_folder = Path(keys_folder) / str(user.id)
    user_keys_folder.mkdir(parents=True, exist_ok=True)
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ho Chi Minh City"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Ho Chi Minh City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, user.organization or "User Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, user.full_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, user.email),
    ])
    
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(subject)  # Self-signed
    cert_builder = cert_builder.not_valid_before(datetime.datetime.utcnow())
    cert_builder = cert_builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    cert_builder = cert_builder.public_key(private_key.public_key())
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    )
    
    certificate = cert_builder.sign(
        private_key=private_key, algorithm=hashes.SHA256()
    )
    
    encrypted_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    
    private_key_path = user_keys_folder / 'private_key.pem'
    cert_path = user_keys_folder / 'certificate.pem'
    
    with open(private_key_path, 'wb') as f:
        f.write(encrypted_key)
    
    with open(cert_path, 'wb') as f:
        f.write(cert_pem)
    
    return {
        'private_key_path': private_key_path,
        'certificate_path': cert_path
    }