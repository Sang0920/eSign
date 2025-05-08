from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, timestamps
from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
from pyhanko.sign.signers import PdfSignatureMetadata
from pyhanko_certvalidator import ValidationContext
from pathlib import Path
import getpass
import logging
import hashlib
import hmac
import os
import base64
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
import datetime
from cryptography import x509

# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('pdf_signer')

# --- Configuration ---
input_pdf_path = Path("asset/PDFs/NPComplete.pdf")
output_pdf_path = Path("asset/PDFs/output_signed_timestamped.pdf")

# Certificate and Key
cert_path = Path("trust_store/certificate_v3.crt")
key_path = Path("trust_store/private_key.pem")
key_is_encrypted = True

# Signature Metadata
signature_meta_config = {
    "location": "Ho Chi Minh City, VN",
    "contact_info": "dothesang20@gmail.com",
    "field_name": "Signature1",
    "reason": "I approve this document"
}

# Timestamp Configuration
TSA_URL = "http://timestamp.digicert.com"

# ------------------------------------------------------------------------
# NEW SECTION: Manual Cryptographic Algorithms Implementation
# ------------------------------------------------------------------------

class CryptoAlgorithms:
    """
    Class demonstrating step-by-step implementations of cryptographic algorithms
    for educational purposes in the "Nghiên cứu về các giải thuật mã hóa và 
    hàm băm để xây dựng ứng dụng chứng thực thông điệp" project.
    """
    
    @staticmethod
    def sha256_manual(message):
        """
        Demonstrates SHA-256 hash calculation step by step.
        
        Args:
            message: The message to hash (string or bytes)
            
        Returns:
            Dictionary containing the hash result and detailed steps
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        # Step 1: Initialize hash object
        hash_obj = hashlib.sha256()
        
        # Step 2: Update hash with message
        hash_obj.update(message)
        
        # Step 3: Get digest in different formats
        hex_digest = hash_obj.hexdigest()
        binary_digest = hash_obj.digest()
        base64_digest = base64.b64encode(binary_digest).decode('ascii')
        
        # Return detailed steps for educational purposes
        return {
            'algorithm': 'SHA-256',
            'input_message': message,
            'input_bytes_length': len(message),
            'hex_digest': hex_digest,
            'binary_digest': binary_digest,
            'base64_digest': base64_digest,
            'digest_length_bits': len(binary_digest) * 8,
            'digest_length_bytes': len(binary_digest)
        }
    
    @staticmethod
    def hmac_sha256_manual(key, message):
        """
        Demonstrates HMAC-SHA256 calculation step by step.
        
        Args:
            key: The key for HMAC (string or bytes)
            message: The message to authenticate (string or bytes)
            
        Returns:
            Dictionary containing the HMAC result and detailed steps
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        # Step 1: Prepare key
        block_size = 64  # SHA-256 block size is 64 bytes
        
        if len(key) > block_size:
            # If key is longer than block size, hash it
            key = hashlib.sha256(key).digest()
        if len(key) < block_size:
            # If key is shorter than block size, pad it with zeros
            key = key + b'\x00' * (block_size - len(key))
            
        # Step 2: Prepare inner and outer padding
        inner_pad = bytes(x ^ 0x36 for x in key)  # XOR with 0x36
        outer_pad = bytes(x ^ 0x5C for x in key)  # XOR with 0x5C
        
        # Step 3: Compute inner hash
        inner_hash = hashlib.sha256(inner_pad + message).digest()
        
        # Step 4: Compute outer hash (final HMAC)
        hmac_digest = hashlib.sha256(outer_pad + inner_hash).digest()
        hmac_hex = binascii.hexlify(hmac_digest).decode('ascii')
        
        # Alternative using the hmac module (to verify correctness)
        hmac_obj = hmac.new(key, message, hashlib.sha256)
        standard_hmac = hmac_obj.digest()
        standard_hmac_hex = hmac_obj.hexdigest()
        
        # Return detailed steps for educational purposes
        return {
            'algorithm': 'HMAC-SHA256',
            'key_length': len(key),
            'message_length': len(message),
            'inner_pad_xor_key': inner_pad[:10] + b'...',  # First 10 bytes for display
            'outer_pad_xor_key': outer_pad[:10] + b'...',  # First 10 bytes for display
            'inner_hash': inner_hash,
            'hmac_digest': hmac_digest,
            'hmac_hex': hmac_hex,
            'standard_hmac_matches': hmac_digest == standard_hmac,
            'standard_hmac_hex': standard_hmac_hex
        }
    
    @staticmethod
    def aes_cbc_manual(key, message, encrypt=True, iv=None):
        """
        Demonstrates AES-CBC encryption/decryption step by step.
        
        Args:
            key: The encryption key (16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
            message: The message to encrypt or decrypt
            encrypt: True for encryption, False for decryption
            iv: Initialization vector (16 bytes). Generated if None
            
        Returns:
            Dictionary containing the result and detailed steps
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(message, str) and encrypt:
            message = message.encode('utf-8')
            
        # Key size validation
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
            
        # Step 1: Generate or validate IV
        if iv is None and encrypt:
            iv = os.urandom(16)  # AES block size is 16 bytes
        elif iv is None and not encrypt:
            raise ValueError("IV is required for decryption")
        elif len(iv) != 16:
            raise ValueError("IV must be 16 bytes")
            
        # Step 2: Apply padding for encryption
        if encrypt:
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(message) + padder.finalize()
            data_to_process = padded_data
        else:
            data_to_process = message
            
        # Step 3: Create cipher and encryptor/decryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        
        if encrypt:
            processor = cipher.encryptor()
            operation = "Encryption"
        else:
            processor = cipher.decryptor()
            operation = "Decryption"
            
        # Step 4: Process the data
        result = processor.update(data_to_process) + processor.finalize()
        
        # Step 5: Remove padding for decryption
        if not encrypt:
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            try:
                result = unpadder.update(result) + unpadder.finalize()
            except ValueError as e:
                return {
                    'success': False,
                    'error': f"Padding error: {str(e)}. This may indicate an incorrect key, IV, or ciphertext."
                }
        
        # Return detailed steps for educational purposes
        return {
            'success': True,
            'algorithm': f'AES-{len(key)*8}-CBC',
            'operation': operation,
            'key_length_bits': len(key) * 8,
            'iv': iv,
            'iv_hex': iv.hex(),
            'input_length': len(message),
            'input_hex': message.hex() if isinstance(message, bytes) else binascii.hexlify(message.encode('utf-8')).decode('ascii') if encrypt else "Binary data",
            'padded_data_length': len(padded_data) if encrypt else "N/A",
            'result': result,
            'result_hex': result.hex(),
            'result_base64': base64.b64encode(result).decode('ascii'),
            'result_length': len(result)
        }
    
    @staticmethod
    def rsa_manual(message, key, encrypt=True, is_private=False):
        """
        Demonstrates RSA encryption/decryption or signing/verification step by step.
        
        Args:
            message: The message to encrypt/decrypt or sign/verify
            key: PEM-encoded key (private or public)
            encrypt: True for encryption/signing, False for decryption/verification
            is_private: True if key is a private key, False if public
            
        Returns:
            Dictionary containing the result and detailed steps
        """
        if isinstance(message, str) and encrypt:
            message = message.encode('utf-8')
            
        # Step 1: Load the key
        if is_private:
            # For private key, check if it's encrypted or not
            try:
                key_obj = load_pem_private_key(key, password=None)
            except TypeError:
                # Key is encrypted, we'll need a password
                password = getpass.getpass("Enter private key password: ").encode('utf-8')
                key_obj = load_pem_private_key(key, password=password)
        else:
            key_obj = load_pem_public_key(key)
            
        # Step 2: Determine key properties
        if is_private:
            key_size = key_obj.key_size
            public_numbers = key_obj.public_key().public_numbers()
            public_exponent = public_numbers.e
            modulus = public_numbers.n
        else:
            key_size = key_obj.key_size
            public_numbers = key_obj.public_numbers()
            public_exponent = public_numbers.e
            modulus = public_numbers.n
            
        # Step 3: Encrypt/decrypt or sign/verify
        if encrypt and not is_private:
            # Public key encryption
            ciphertext = key_obj.encrypt(
                message,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            operation = "Encryption (public key)"
            result = ciphertext
        elif not encrypt and is_private:
            # Private key decryption
            try:
                plaintext = key_obj.decrypt(
                    message,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                operation = "Decryption (private key)"
                result = plaintext
            except Exception as e:
                return {
                    'success': False,
                    'error': f"Decryption error: {str(e)}. This may indicate incorrect key or ciphertext."
                }
        elif encrypt and is_private:
            # Private key signing
            signature = key_obj.sign(
                message,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            operation = "Signing (private key)"
            result = signature
        elif not encrypt and not is_private:
            # Public key verification
            try:
                # For verification, message is the original message, and we need a separate signature
                signature = message  # In this case, message is actually the signature
                # We would need the original message to verify, but here we're just showing the process
                # key_obj.verify(signature, original_message, padding, algorithm)
                operation = "Verification (public key)"
                result = b"Verification would be performed here with original message"
            except Exception as e:
                return {
                    'success': False,
                    'error': f"Verification error: {str(e)}"
                }
        
        # Return detailed steps for educational purposes
        return {
            'success': True,
            'algorithm': 'RSA',
            'key_size_bits': key_size,
            'public_exponent': public_exponent,
            'modulus_hex': f"{modulus:x}"[:20] + "...",  # First 20 hex digits
            'operation': operation,
            'input_length': len(message),
            'result': result,
            'result_hex': result.hex(),
            'result_base64': base64.b64encode(result).decode('ascii'),
            'result_length': len(result)
        }

# ------------------------------------------------------------------------
# OpenSSL CLI Commands Translated to Python
# ------------------------------------------------------------------------

class OpenSSLPython:
    """
    Class providing Python equivalents to OpenSSL CLI commands.
    For the "Nghiên cứu về các giải thuật mã hóa và hàm băm để xây dựng 
    ứng dụng chứng thực thông điệp" project.
    """
    
    @staticmethod
    def generate_rsa_key(bits=2048, output_file="private_key.pem", passphrase=None, exponent=65537):
        """
        Python equivalent to:
        openssl genrsa -aes256 -out private_key.pem 2048
        
        Args:
            bits: Key size in bits
            output_file: Path to save the private key
            passphrase: Optional passphrase to encrypt the key
            exponent: Public exponent (default 65537)
            
        Returns:
            Path to the generated key file
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=exponent,
            key_size=bits
        )
        
        # Determine encryption algorithm based on whether passphrase is provided
        if passphrase:
            if isinstance(passphrase, str):
                passphrase = passphrase.encode('utf-8')
                
            encryption_algorithm = PrivateFormat.PKCS8
        else:
            encryption_algorithm = NoEncryption()
            
        # Serialize and save the private key
        with open(output_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            ))
            
        logger.info(f"RSA private key generated and saved to {output_file}")
        return output_file
    
    @staticmethod
    def extract_public_key(private_key_file, output_file="public_key.pem", passphrase=None):
        """
        Python equivalent to:
        openssl rsa -in private_key.pem -pubout -out public_key.pem
        
        Args:
            private_key_file: Path to the private key
            output_file: Path to save the public key
            passphrase: Optional passphrase for the private key
            
        Returns:
            Path to the extracted public key
        """
        # Read private key
        with open(private_key_file, 'rb') as f:
            private_key_data = f.read()
            
        # Load private key
        if passphrase:
            if isinstance(passphrase, str):
                passphrase = passphrase.encode('utf-8')
                
            private_key = load_pem_private_key(private_key_data, password=passphrase)
        else:
            private_key = load_pem_private_key(private_key_data, password=None)
            
        # Extract public key
        public_key = private_key.public_key()
        
        # Serialize and save the public key
        with open(output_file, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ))
            
        logger.info(f"Public key extracted and saved to {output_file}")
        return output_file
    
    @staticmethod
    def create_self_signed_cert(private_key_file, output_cert="certificate.crt", passphrase=None, 
                              country="VN", state="Ho Chi Minh City", city="Ho Chi Minh City",
                              org="HUIT", org_unit="HUIT Lab", common_name="Do The Sang", 
                              email="dothesang20@gmail.com", days=365):
        """
        Python equivalent to:
        openssl req -x509 -new -key private_key.pem -sha256 -days 365 -out certificate_v3.crt -config openssl.cnf
        
        Args:
            private_key_file: Path to the private key
            output_cert: Path to save the certificate
            passphrase: Optional passphrase for the private key
            country, state, city, org, org_unit, common_name, email: Certificate subject fields
            days: Certificate validity in days
            
        Returns:
            Path to the generated certificate
        """
        # Read private key
        with open(private_key_file, 'rb') as f:
            private_key_data = f.read()
            
        # Load private key
        if passphrase:
            if isinstance(passphrase, str):
                passphrase = passphrase.encode('utf-8')
                
            private_key = load_pem_private_key(private_key_data, password=passphrase)
        else:
            private_key = load_pem_private_key(private_key_data, password=None)
            
        # Create certificate subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, city),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)
        ])
        
        # Calculate validity period
        now = datetime.datetime.utcnow()
        validity_end = now + datetime.timedelta(days=days)
        
        # Create certificate
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject  # Self-signed, so issuer = subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            validity_end
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,  # Non-repudiation
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Sign the certificate with the private key
        certificate = cert_builder.sign(
            private_key,
            hashes.SHA256()
        )
        
        # Serialize and save the certificate
        with open(output_cert, 'wb') as f:
            f.write(certificate.public_bytes(Encoding.PEM))
            
        logger.info(f"Self-signed certificate generated and saved to {output_cert}")
        return output_cert
    
    @staticmethod
    def view_certificate(cert_file):
        """
        Python equivalent to:
        openssl x509 -in certificate.crt -text -noout
        
        Args:
            cert_file: Path to the certificate file
            
        Returns:
            Dictionary containing certificate details
        """
        # Read certificate
        with open(cert_file, 'rb') as f:
            cert_data = f.read()
            
        # Load certificate
        cert = load_pem_x509_certificate(cert_data)
        
        # Extract certificate details
        subject = cert.subject
        issuer = cert.issuer
        valid_from = cert.not_valid_before
        valid_to = cert.not_valid_after
        serial = cert.serial_number
        version = cert.version
        signature_algorithm = cert.signature_algorithm_oid._name
        
        # Extract subject components
        subject_dict = {}
        for attr in subject:
            oid_name = attr.oid._name
            value = attr.value
            subject_dict[oid_name] = value
            
        # Extract issuer components
        issuer_dict = {}
        for attr in issuer:
            oid_name = attr.oid._name
            value = attr.value
            issuer_dict[oid_name] = value
            
        # Extract extensions
        extensions = {}
        for ext in cert.extensions:
            ext_name = ext.oid._name
            extensions[ext_name] = str(ext.value)
            
        # Format the results
        cert_info = {
            'version': version.name,
            'serial_number': f"{serial:x}",
            'signature_algorithm': signature_algorithm,
            'issuer': issuer_dict,
            'validity': {
                'not_before': valid_from.strftime('%Y-%m-%d %H:%M:%S'),
                'not_after': valid_to.strftime('%Y-%m-%d %H:%M:%S')
            },
            'subject': subject_dict,
            'extensions': extensions,
            'public_key': {
                'algorithm': cert.public_key().key_size,
                'bits': cert.public_key().key_size
            }
        }
        
        return cert_info
    
    @staticmethod
    def hash_file(file_path, algorithm='sha256'):
        """
        Python equivalent to:
        openssl dgst -sha256 file.txt
        
        Args:
            file_path: Path to the file to hash
            algorithm: Hash algorithm to use
            
        Returns:
            Dictionary containing hash result
        """
        # Check file exists
        if not Path(file_path).exists():
            return {'error': f"File not found: {file_path}"}
            
        # Select hash algorithm
        hash_func = getattr(hashlib, algorithm, None)
        if not hash_func:
            return {'error': f"Unsupported hash algorithm: {algorithm}"}
            
        # Calculate hash
        hash_obj = hash_func()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
                
        digest = hash_obj.hexdigest()
        
        return {
            'algorithm': algorithm,
            'file': file_path,
            'digest': digest
        }

def sign_pdf_with_timestamp(
    input_path: Path,
    output_path: Path,
    cert_file: Path,
    key_file: Path,
    key_passphrase: str = None,
    tsa_url: str = None,
    meta: dict = None
):
    """
    Signs a PDF with timestamp from a TSA server.
    """
    if meta is None:
        meta = {}
        
    field_name = meta.get('field_name', 'Signature1')
    
    try:
        # Load signer credentials
        signer = signers.SimpleSigner.load(
            key_file=str(key_file),
            cert_file=str(cert_file),
            key_passphrase=key_passphrase.encode('utf-8') if key_passphrase else None
        )
        logger.info("Signer certificate loaded successfully.")
        
        # Create timestamp client if URL provided
        timestamper = None
        if tsa_url:
            timestamper = timestamps.HTTPTimeStamper(tsa_url)
            logger.info(f"Timestamp service configured: {tsa_url}")
        
    except Exception as e:
        logger.error(f"Error loading certificate/key: {e}")
        return False

    try:
        # Open the input PDF
        with open(input_path, 'rb') as inf:
            # Create the writer for generating a new revision with signature
            w = IncrementalPdfFileWriter(inf)
            
            # Load certificate properly instead of using raw bytes
            with open(cert_file, 'rb') as cert_data:
                cert_bytes = cert_data.read()
                # Parse the certificate to get a certificate object
                try:
                    from asn1crypto import pem, x509 as asn1_x509
                    
                    # Check if it's PEM format
                    if pem.detect(cert_bytes):
                        _, _, cert_bytes = pem.unarmor(cert_bytes)
                    
                    # Create validation context without using trust_roots
                    validation_context = ValidationContext()
                    
                except ImportError:
                    # Fallback to a simpler approach if asn1crypto is not available
                    logger.warning("asn1crypto not available, falling back to simpler signing method")
                    return sign_pdf_simple_timestamp(
                        input_path=input_path,
                        output_path=output_path,
                        cert_file=cert_file,
                        key_file=key_file,
                        key_passphrase=key_passphrase,
                        tsa_url=tsa_url,
                        meta=meta
                    )
            
            # Create signature metadata - not using validation context to avoid the error
            cms_meta = PdfSignatureMetadata(
                field_name=field_name,
                reason=meta.get('reason'),
                location=meta.get('location'),
                contact_info=meta.get('contact_info'),
                subfilter=SigSeedSubFilter.PADES,
                md_algorithm='sha256'
            )
            
            # Create signature field specification
            sig_field_spec = SigFieldSpec(
                sig_field_name=field_name,
                box=(50, 50, 250, 100)  # Position the signature field
            )
            
            # Sign the PDF 
            with open(output_path, 'wb') as out:
                signers.sign_pdf(
                    pdf_out=w,
                    signature_meta=cms_meta,
                    signer=signer,
                    timestamper=timestamper,
                    output=out,
                    new_field_spec=sig_field_spec,
                    existing_fields_only=False
                )
                
            logger.info(f"PDF successfully signed with timestamp and saved to: {output_path}")
            return True
            
    except Exception as e:
        logger.error(f"Error during PDF signing: {e}")
        import traceback
        traceback.print_exc()
        return False

# --- Alternative option without validation info ---
def sign_pdf_simple_timestamp(
    input_path: Path,
    output_path: Path,
    cert_file: Path,
    key_file: Path,
    key_passphrase: str = None,
    tsa_url: str = None,
    meta: dict = None
):
    """
    Signs a PDF with timestamp without embedding validation info.
    Use this if you have issues with the validation context.
    """
    if meta is None:
        meta = {}
        
    field_name = meta.get('field_name', 'Signature1')
    
    try:
        # Load signer credentials
        signer = signers.SimpleSigner.load(
            key_file=str(key_file),
            cert_file=str(cert_file),
            key_passphrase=key_passphrase.encode('utf-8') if key_passphrase else None
        )
        logger.info("Signer certificate loaded successfully.")
        
        # Create timestamp client if URL provided
        timestamper = None
        if tsa_url:
            timestamper = timestamps.HTTPTimeStamper(tsa_url)
            logger.info(f"Timestamp service configured: {tsa_url}")
        
    except Exception as e:
        logger.error(f"Error loading certificate/key: {e}")
        return False

    try:
        # Open the input PDF
        with open(input_path, 'rb') as inf:
            # Create the writer for generating a new revision with signature
            w = IncrementalPdfFileWriter(inf)
            
            # Create signature metadata without validation info
            cms_meta = PdfSignatureMetadata(
                field_name=field_name,
                reason=meta.get('reason'),
                location=meta.get('location'),
                contact_info=meta.get('contact_info'),
                subfilter=SigSeedSubFilter.PADES,
                md_algorithm='sha256'
                # No embed_validation_info here
            )
            
            # Create signature field specification
            sig_field_spec = SigFieldSpec(
                sig_field_name=field_name,
                box=(50, 50, 250, 100)  # Position the signature field
            )
            
            # Sign the PDF 
            with open(output_path, 'wb') as out:
                signers.sign_pdf(
                    pdf_out=w,
                    signature_meta=cms_meta,
                    signer=signer,
                    timestamper=timestamper,
                    output=out,
                    new_field_spec=sig_field_spec,
                    existing_fields_only=False
                )
                
            logger.info(f"PDF successfully signed with timestamp and saved to: {output_path}")
            return True
            
    except Exception as e:
        logger.error(f"Error during PDF signing: {e}")
        import traceback
        traceback.print_exc()
        return False

# ------------------------------------------------------------------------
# Demo functionality for cryptographic algorithms
# ------------------------------------------------------------------------

def run_crypto_demos():
    """Run demonstrations of cryptographic algorithms for the project"""
    
    logger.info("Running cryptographic algorithm demonstrations")
    
    # 1. SHA-256 demonstration
    message = "Nghiên cứu về các giải thuật mã hóa và hàm băm để xây dựng ứng dụng chứng thực thông điệp"
    sha256_result = CryptoAlgorithms.sha256_manual(message)
    logger.info(f"SHA-256 of message: {sha256_result['hex_digest']}")
    
    # 2. HMAC-SHA256 demonstration
    key = "huit-secret-key-2025"
    hmac_result = CryptoAlgorithms.hmac_sha256_manual(key, message)
    logger.info(f"HMAC-SHA256 of message: {hmac_result['hmac_hex']}")
    
    # 3. AES-CBC demonstration
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)       # 128-bit IV
    
    # Encrypt
    encrypt_result = CryptoAlgorithms.aes_cbc_manual(aes_key, message, encrypt=True, iv=iv)
    logger.info(f"AES-256-CBC encrypted: {encrypt_result['result_base64']}")
    
    # Decrypt
    decrypt_result = CryptoAlgorithms.aes_cbc_manual(aes_key, encrypt_result['result'], encrypt=False, iv=iv)
    if decrypt_result['success']:
        decrypted_text = decrypt_result['result'].decode('utf-8')
        logger.info(f"AES-256-CBC decrypted: {decrypted_text}")
        logger.info(f"Decryption successful: {decrypted_text == message}")
    
    # Note: RSA demo would require generating keys first, which is covered in the OpenSSLPython class
    
    logger.info("Cryptographic algorithm demonstrations completed")
    return {
        'sha256': sha256_result,
        'hmac': hmac_result,
        'aes_encrypt': encrypt_result,
        'aes_decrypt': decrypt_result
    }

# --- Main Execution ---
if __name__ == "__main__":
    # Display current date and user info
    current_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"Current Date and Time (UTC): {current_time}")
    logger.info("Current User's Login: Sang0920")
    logger.info("Project: Nghiên cứu về các giải thuật mã hóa và hàm băm để xây dựng ứng dụng chứng thực thông điệp")
    
    # Choose which functionality to run
    # 1. PDF signing
    # 2. Crypto algorithm demos
    # 3. OpenSSL equivalents
    action = 1  # Default to PDF signing
    
    try:
        action = int(input("Select action (1=Sign PDF, 2=Crypto Demos, 3=OpenSSL operations): "))
    except ValueError:
        logger.info("Invalid selection, defaulting to PDF signing")
    
    if action == 2:
        # Run cryptographic algorithm demonstrations
        demo_results = run_crypto_demos()
        exit(0)
    elif action == 3:
        # Run OpenSSL equivalent operations
        try:
            openssl_action = int(input(
                "Select OpenSSL operation:\n"
                "1. Generate RSA key\n"
                "2. Extract public key\n"
                "3. Create self-signed certificate\n"
                "4. View certificate details\n"
                "5. Hash a file\n"
                "Selection: "
            ))
            
            if openssl_action == 1:
                bits = int(input("Key size in bits (e.g., 2048): "))
                output_file = input("Output file (press Enter for private_key.pem): ") or "private_key.pem"
                use_passphrase = input("Encrypt key with passphrase? (y/n): ").lower() == 'y'
                passphrase = getpass.getpass("Enter passphrase: ") if use_passphrase else None
                
                OpenSSLPython.generate_rsa_key(bits, output_file, passphrase)
                
            elif openssl_action == 2:
                private_key_file = input("Private key file: ")
                output_file = input("Output file (press Enter for public_key.pem): ") or "public_key.pem"
                use_passphrase = input("Is private key encrypted? (y/n): ").lower() == 'y'
                passphrase = getpass.getpass("Enter passphrase: ") if use_passphrase else None
                
                OpenSSLPython.extract_public_key(private_key_file, output_file, passphrase)
                
            elif openssl_action == 3:
                private_key_file = input("Private key file: ")
                output_cert = input("Output certificate file (press Enter for certificate.crt): ") or "certificate.crt"
                use_passphrase = input("Is private key encrypted? (y/n): ").lower() == 'y'
                passphrase = getpass.getpass("Enter passphrase: ") if use_passphrase else None
                
                # Use default values for certificate fields, or prompt for them
                use_defaults = input("Use default certificate fields? (y/n): ").lower() == 'y'
                
                if use_defaults:
                    OpenSSLPython.create_self_signed_cert(private_key_file, output_cert, passphrase)
                else:
                    country = input("Country (2-letter code): ")
                    state = input("State/Province: ")
                    city = input("City/Locality: ")
                    org = input("Organization: ")
                    org_unit = input("Organizational Unit: ")
                    common_name = input("Common Name: ")
                    email = input("Email: ")
                    days = int(input("Validity period in days: "))
                    
                    OpenSSLPython.create_self_signed_cert(
                        private_key_file, output_cert, passphrase,
                        country, state, city, org, org_unit, common_name, email, days
                    )
                    
            elif openssl_action == 4:
                cert_file = input("Certificate file: ")
                cert_info = OpenSSLPython.view_certificate(cert_file)
                
                # Display certificate info
                print("\nCertificate details:")
                print(f"Version: {cert_info['version']}")
                print(f"Serial Number: {cert_info['serial_number']}")
                print(f"Signature Algorithm: {cert_info['signature_algorithm']}")
                
                print("\nIssuer:")
                for k, v in cert_info['issuer'].items():
                    print(f"  {k}: {v}")
                    
                print("\nValidity:")
                for k, v in cert_info['validity'].items():
                    print(f"  {k}: {v}")
                    
                print("\nSubject:")
                for k, v in cert_info['subject'].items():
                    print(f"  {k}: {v}")
                    
                print("\nExtensions:")
                for k, v in cert_info['extensions'].items():
                    print(f"  {k}: {v}")
                    
            elif openssl_action == 5:
                file_path = input("File to hash: ")
                algorithm = input("Hash algorithm (press Enter for sha256): ") or "sha256"
                
                hash_result = OpenSSLPython.hash_file(file_path, algorithm)
                if 'error' in hash_result:
                    print(f"Error: {hash_result['error']}")
                else:
                    print(f"{algorithm}({file_path})= {hash_result['digest']}")
                    
            else:
                logger.info("Invalid OpenSSL operation selection")
                
        except Exception as e:
            logger.error(f"Error performing OpenSSL operation: {e}")
            
        exit(0)
    
    # Continue with PDF signing if action == 1 or invalid
    
    # 1. Basic Input Checks
    if not input_pdf_path.is_file():
        logger.error(f"Error: Input PDF not found at '{input_pdf_path}'")
        exit(1)
    if not cert_path.is_file():
        logger.error(f"Error: Certificate file not found at '{cert_path}'")
        exit(1)
    if not key_path.is_file():
        logger.error(f"Error: Private key file not found at '{key_path}'")
        exit(1)

    # 2. Get Key Passphrase if needed
    passphrase = None
    if key_is_encrypted:
        try:
            passphrase = getpass.getpass(f"Enter passphrase for private key '{key_path.name}': ")
        except Exception as e:
            logger.error(f"Could not read passphrase: {e}")
            exit(1)
        if not passphrase:
            logger.error("Passphrase not provided. Exiting.")
            exit(1)

    # 3. First try with simplified signing
    logger.info("Attempting to sign PDF with timestamp...")
    success = sign_pdf_simple_timestamp(
        input_path=input_pdf_path,
        output_path=output_pdf_path,
        cert_file=cert_path,
        key_file=key_path,
        key_passphrase=passphrase,
        tsa_url=TSA_URL,
        meta=signature_meta_config
    )

    if success:
        logger.info(f"Process complete. Final signed PDF is at: {output_pdf_path}")
    else:
        logger.error("Signing process failed.")
        exit(1)