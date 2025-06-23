from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, timestamps
from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
from pyhanko.sign.signers import PdfSignatureMetadata
from pyhanko_certvalidator import ValidationContext
from pathlib import Path
import logging
import datetime
import fitz  # PyMuPDF
import traceback

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('pdf_signer')

input_pdf_path = Path("asset/PDFs/NPComplete.pdf")
output_pdf_path = Path("asset/PDFs/output_signed_timestamped.pdf")

cert_path = Path("trust_store/certificate_v3.crt")
key_path = Path("trust_store/private_key.pem")
key_is_encrypted = True

signature_meta_config = {
    "location": "Ho Chi Minh City, VN",
    "contact_info": "dothesang20@gmail.com",
    "field_name": "Signature1",
    "reason": "I approve this document"
}

TSA_URL = "http://timestamp.digicert.com"

def add_visual_text_and_prepare_sig_field(
    input_path: Path, text: str, rect: fitz.Rect, page_num: int,
    font_size: int, sig_field_name: str = 'Signature1'
) -> bytes:
    doc = fitz.open(input_path)
    if page_num >= len(doc):
        logger.error(f"Error: Page number {page_num} is out of range.")
        return None
    page = doc[page_num]
    page.insert_textbox(
        rect, text, fontsize=font_size, fontname="helv", color=(0, 0, 0), align=fitz.TEXT_ALIGN_LEFT,
    )
    logger.info(f"Visual text added to page {page_num} at rectangle {rect}.")
    pdf_bytes = doc.tobytes(incremental=False, garbage=4, deflate=True)
    doc.close()
    return pdf_bytes

def add_visual_image_and_prepare_sig_field(
    input_path: Path, image_path: Path, rect: fitz.Rect, page_num: int,
    sig_field_name: str = 'Signature1'
) -> bytes:
    try:
        doc = fitz.open(input_path)
        if page_num >= len(doc):
            logger.error(f"Error: Page number {page_num} is out of range.")
            return None
            
        page = doc[page_num]
        
        if not image_path.exists():
            logger.error(f"Image file not found: {image_path}")
            return None
            
        try:
            page.insert_image(rect, filename=str(image_path))
            logger.info(f"Image signature added to page {page_num} at rectangle {rect}.")
        except Exception as e:
            logger.error(f"Failed to insert image: {e}")
            return None
            
        pdf_bytes = doc.tobytes(incremental=False, garbage=4, deflate=True)
        doc.close()
        return pdf_bytes
        
    except Exception as e:
        logger.error(f"Error adding image to PDF: {e}")
        traceback.print_exc()
        return None
# Update the signing function to accept image parameters
def sign_pdf_with_timestamp(
    input_path: Path,
    output_path: Path,
    cert_file: Path,
    key_file: Path,
    key_passphrase: str = None,
    tsa_url: str = None,
    meta: dict = None,
    signature_image: Path = None,
    signature_page: int = 0,
    signature_rect: tuple = (50, 50, 250, 100)
):
    """
    Signs a PDF with timestamp from a TSA server.
    """
    if meta is None:
        meta = {}
        
    field_name = meta.get('field_name', 'Signature1')
    
    try:
        signer = signers.SimpleSigner.load(
            key_file=str(key_file),
            cert_file=str(cert_file),
            key_passphrase=key_passphrase.encode('utf-8') if key_passphrase else None
        )
        logger.info("Signer certificate loaded successfully.")
        
        timestamper = None
        if tsa_url:
            timestamper = timestamps.HTTPTimeStamper(tsa_url)
            logger.info(f"Timestamp service configured: {tsa_url}")
        
    except Exception as e:
        logger.error(f"Error loading certificate/key: {e}")
        return False

    try:
        pdf_data = None
        temp_input_path = input_path
        
        if signature_image:
            rect = fitz.Rect(*signature_rect)
            pdf_bytes = add_visual_image_and_prepare_sig_field(
                input_path=input_path,
                image_path=signature_image,
                rect=rect,
                page_num=signature_page,
                sig_field_name=field_name
            )
            
            if pdf_bytes is None:
                logger.error("Failed to add image signature to PDF")
                return False
                
            temp_input_path = Path(f"{input_path.stem}_with_sig{input_path.suffix}")
            with open(temp_input_path, 'wb') as f:
                f.write(pdf_bytes)
            logger.info(f"Created intermediate PDF with image signature at {temp_input_path}")
        
        with open(temp_input_path, 'rb') as inf:
            w = IncrementalPdfFileWriter(inf)
            
            cms_meta = PdfSignatureMetadata(
                field_name=field_name,
                reason=meta.get('reason'),
                location=meta.get('location'),
                contact_info=meta.get('contact_info'),
                subfilter=SigSeedSubFilter.PADES,
                md_algorithm='sha256'
            )
            
            with open(output_path, 'wb') as out:
                signers.sign_pdf(
                    pdf_out=w,
                    signature_meta=cms_meta,
                    signer=signer,
                    timestamper=timestamper,
                    output=out,
                    existing_fields_only=False
                )
            
            if signature_image and temp_input_path != input_path:
                try:
                    temp_input_path.unlink()
                    logger.info(f"Removed temporary file {temp_input_path}")
                except:
                    logger.warning(f"Could not remove temporary file {temp_input_path}")
                
            logger.info(f"PDF successfully signed with timestamp and saved to: {output_path}")
            return True
            
    except Exception as e:
        logger.error(f"Error during PDF signing: {e}")
        traceback.print_exc()
        return False

# --- Alternative option for more advanced use cases ---
def sign_pdf_with_validation(
    input_path: Path,
    output_path: Path,
    cert_file: Path,
    key_file: Path,
    key_passphrase: str = None,
    tsa_url: str = None,
    meta: dict = None,
    trust_roots_path: Path = None
):
    """
    Signs a PDF with timestamp and validation info.
    Use this when you have proper trust roots for validation.
    
    Args:
        input_path: Path to input PDF
        output_path: Path to save the signed PDF
        cert_file: Path to certificate file
        key_file: Path to private key file
        key_passphrase: Passphrase for private key
        tsa_url: Timestamp authority URL
        meta: Metadata for signature
        trust_roots_path: Path to directory with trusted CA certificates
    """
    if meta is None:
        meta = {}
        
    field_name = meta.get('field_name', 'Signature1')
    
    try:
        signer = signers.SimpleSigner.load(
            key_file=str(key_file),
            cert_file=str(cert_file),
            key_passphrase=key_passphrase.encode('utf-8') if key_passphrase else None
        )
        logger.info("Signer certificate loaded successfully.")
        
        timestamper = None
        if tsa_url:
            timestamper = timestamps.HTTPTimeStamper(tsa_url)
            logger.info(f"Timestamp service configured: {tsa_url}")
        
    except Exception as e:
        logger.error(f"Error loading certificate/key: {e}")
        return False

    try:
        with open(input_path, 'rb') as inf:
            w = IncrementalPdfFileWriter(inf)
            
            validation_context = None
            if trust_roots_path and trust_roots_path.is_dir():
                trust_roots = []
                
                for cert_file_path in trust_roots_path.glob('*.pem'):
                    try:
                        with open(cert_file_path, 'rb') as f:
                            trust_roots.append(f.read())
                        logger.info(f"Added trusted root: {cert_file_path.name}")
                    except Exception as e:
                        logger.warning(f"Could not load certificate {cert_file_path}: {e}")
                
                for cert_file_path in trust_roots_path.glob('*.crt'):
                    try:
                        with open(cert_file_path, 'rb') as f:
                            trust_roots.append(f.read())
                        logger.info(f"Added trusted root: {cert_file_path.name}")
                    except Exception as e:
                        logger.warning(f"Could not load certificate {cert_file_path}: {e}")
                
                if trust_roots:
                    try:
                        validation_context = ValidationContext(trust_roots=trust_roots)
                    except Exception as e:
                        logger.warning(f"Could not create validation context: {e}")
                        validation_context = None
            
            cms_meta = PdfSignatureMetadata(
                field_name=field_name,
                reason=meta.get('reason'),
                location=meta.get('location'),
                contact_info=meta.get('contact_info'),
                subfilter=SigSeedSubFilter.PADES,
                md_algorithm='sha256'
            )
            
            if validation_context:
                cms_meta.validation_context = validation_context
                cms_meta.embed_validation_info = True
                logger.info("Using validation context with trust roots")
            
            sig_field_spec = SigFieldSpec(
                sig_field_name=field_name,
                box=(50, 50, 250, 100)  # Position the signature field,
            )
            
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
                
            logger.info(f"PDF successfully signed with validation info and saved to: {output_path}")
            return True
            
    except Exception as e:
        logger.error(f"Error during PDF signing with validation: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    current_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"Current Date and Time (UTC): {current_time}")
    logger.info("Current User's Login: Sang0920")
    
    if not input_pdf_path.is_file():
        logger.error(f"Error: Input PDF not found at '{input_pdf_path}'")
        exit(1)
    if not cert_path.is_file():
        logger.error(f"Error: Certificate file not found at '{cert_path}'")
        exit(1)
    if not key_path.is_file():
        logger.error(f"Error: Private key file not found at '{key_path}'")
        exit(1)

    passphrase = None
    if key_is_encrypted:
        try:
            # passphrase = getpass.getpass(f"Enter passphrase for private key '{key_path.name}': ")
            passphrase = 'sang0920'  # Hardcoded for testing; replace with secure input in production
        except Exception as e:
            logger.error(f"Could not read passphrase: {e}")
            exit(1)
        if not passphrase:
            logger.error("Passphrase not provided. Exiting.")
            exit(1)
            
    # signature_text = input("Enter your signature text to display on the PDF: ")
    # logger.info(f"Custom signature text provided: {signature_text}")
    
    signature_page = 0
    signature_rect = (50, 700, 300, 750)  # x1, y1, x2, y2 coordinates
    
    try:
        page_input = input("Enter page number for signature (0 for first page, press Enter for default): ")
        if page_input.strip():
            signature_page = int(page_input)
    except ValueError:
        logger.warning("Invalid page number input, using default page 0")
        signature_page = 0

    image_path_str = input("Enter path to your signature image (PNG/JPG): ")
    signature_image_path = Path(image_path_str)
    if not signature_image_path.exists():
        logger.error(f"Signature image not found at '{signature_image_path}'")
        exit(1)
    logger.info(f"Using signature image: {signature_image_path}")
    
    signature_page = 0
    signature_rect = (400, 700, 550, 750)  # x1, y1, x2, y2 coordinates (adjusted for image)
    
    try:
        page_input = input("Enter page number for signature (0 for first page, press Enter for default): ")
        if page_input.strip():
            signature_page = int(page_input)
    except ValueError:
        logger.warning("Invalid page number input, using default page 0")
        signature_page = 0

    logger.info("Signing PDF with timestamp...")
    success = sign_pdf_with_timestamp(
        input_path=input_pdf_path,
        output_path=output_pdf_path,
        cert_file=cert_path,
        key_file=key_path,
        key_passphrase=passphrase,
        tsa_url=TSA_URL,
        meta=signature_meta_config,
        signature_image=signature_image_path,
        signature_page=signature_page,
        signature_rect=signature_rect
    )

    if success:
        logger.info(f"Process complete. Final signed PDF is at: {output_pdf_path}")
    else:
        logger.error("Signing process failed.")
        exit(1)
