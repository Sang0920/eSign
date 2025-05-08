from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, timestamps
from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
from pyhanko.sign.signers import PdfSignatureMetadata
from pyhanko_certvalidator import ValidationContext
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from pathlib import Path
import getpass
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('pdf_signer')

# --- Configuration ---
input_pdf_path = Path("NPComplete.pdf")
output_pdf_path = Path("output_signed_vnca.pdf")

# Certificate and Key
cert_path = Path("certificate_v3.crt")
key_path = Path("private_key.pem")
key_is_encrypted = True

# Vietnam Root CA
vietnam_ca_path = Path("trust_store/vietnam_national_ca_g3.pem")
# Also check the .cer file if the .pem file doesn't exist
if not vietnam_ca_path.exists():
    vietnam_ca_path = Path("trust_store/vnrca-g3.cer")

# Signature Metadata
signature_meta_config = {
    "location": "Ho Chi Minh City, VN",
    "contact_info": "dothesang20@gmail.com",
    "field_name": "Signature1",
    "reason": "I approve this document"
}

# Timestamp Configuration
TSA_URL = "http://timestamp.digicert.com"

def sign_pdf_with_timestamp(
    input_path: Path,
    output_path: Path,
    cert_file: Path,
    key_file: Path,
    key_passphrase: str = None,
    tsa_url: str = None,
    vietnam_ca_file: Path = None,
    meta: dict = None
):
    """
    Signs a PDF with timestamp and Vietnam CA root.
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
            
            # Create signature metadata
            cms_meta = PdfSignatureMetadata(
                field_name=field_name,
                reason=meta.get('reason'),
                location=meta.get('location'),
                contact_info=meta.get('contact_info'),
                subfilter=SigSeedSubFilter.PADES,
                md_algorithm='sha256'
            )
            
            # Create signature field specification with a visual appearance box
            # Removed the problematic doc_mdp_update_value parameter
            sig_field_spec = SigFieldSpec(
                sig_field_name=field_name,
                box=(50, 50, 250, 100)
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

# --- Main Execution ---
if __name__ == "__main__":
    # 0. Display current date and user
    current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"Current date: {current_date} | User: Sang0920")
    
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
    
    # Check for Vietnam CA certificate
    if vietnam_ca_path.is_file():
        logger.info(f"Vietnam National Root CA found at: {vietnam_ca_path}")
    else:
        logger.warning(f"Vietnam National Root CA not found at: {vietnam_ca_path}")
        logger.warning("This won't affect the signing process, but the certificate issuer will remain unknown")
        
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

    # 3. Sign with timestamp
    logger.info("Signing PDF with timestamp...")
    success = sign_pdf_with_timestamp(
        input_path=input_pdf_path,
        output_path=output_pdf_path,
        cert_file=cert_path,
        key_file=key_path,
        key_passphrase=passphrase,
        tsa_url=TSA_URL,
        vietnam_ca_file=vietnam_ca_path if vietnam_ca_path.exists() else None,
        meta=signature_meta_config
    )

    if success:
        logger.info(f"Process complete. Final signed PDF is at: {output_pdf_path}")
        logger.info("Note: The Certificate issuer will still show as 'unknown' because your certificate")
        logger.info("is self-signed. For NEAC compliance, you must obtain a certificate from a")
        logger.info("recognized Vietnamese CA that chains to the Vietnam National Root CA.")
    else:
        logger.error("Signing process failed.")
        exit(1)