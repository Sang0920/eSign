import os
import fitz  # PyMuPDF
from PIL import Image
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, timestamps
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.signers import PdfSignatureMetadata

def add_image_signature_to_pdf(input_path, image_path, output_path, browser_coordinates, page_num=0):
    """
    Add a signature image to a PDF file with proper coordinate conversion
    
    browser_coordinates: tuple of (x1, y1, x2, y2) in browser coordinate space
    """
    doc = fitz.open(input_path)
    
    if page_num >= len(doc):
        raise ValueError(f"Page number {page_num} out of range.")
    page = doc[page_num]
    
    page_width, page_height = page.rect.width, page.rect.height
    
    x1, y1, x2, y2 = browser_coordinates
    
    img_width = x2 - x1
    img_height = y2 - y1
    
    img_pix = fitz.Pixmap(image_path)
    sig_width, sig_height = img_pix.width, img_pix.height
    
    tmp_img_path = image_path.parent / f"tmp_{image_path.name}"
    img = Image.open(image_path)
    img = img.resize((int(img_width * 2), int(img_height * 2)), Image.LANCZOS)
    img.save(tmp_img_path)
    
    try:
        rect = fitz.Rect(x1, y1, x2, y2)
        
        page.insert_image(rect, filename=str(tmp_img_path))
        
        os.remove(tmp_img_path)
    except Exception as e:
        if os.path.exists(tmp_img_path):
            os.remove(tmp_img_path)
        raise ValueError(f"Error inserting image: {str(e)}")
    
    doc.save(output_path)
    doc.close()
    
    return output_path

def sign_pdf_with_timestamp(
    input_path,
    output_path,
    cert_path,
    key_path,
    key_passphrase,
    tsa_url,
    metadata
):
    """Sign a PDF with digital signature and timestamp using the specified algorithm"""
    signer = signers.SimpleSigner.load(
        key_file=str(key_path),
        cert_file=str(cert_path),
        key_passphrase=key_passphrase.encode('utf-8')
    )
    
    timestamper = None
    if tsa_url:
        timestamper = timestamps.HTTPTimeStamper(tsa_url)
    
    md_algorithm = metadata.get('md_algorithm', 'sha256')
    
    signature_meta = PdfSignatureMetadata(
        field_name=metadata.get('field_name', 'Signature1'),
        reason=metadata.get('reason', 'I approve this document'),
        location=metadata.get('location', 'Ho Chi Minh City, VN'),
        contact_info=metadata.get('contact_info', ''),
        subfilter=SigSeedSubFilter.PADES,
        md_algorithm=md_algorithm
    )
    
    with open(input_path, 'rb') as inf, open(output_path, 'wb') as outf:
        w = IncrementalPdfFileWriter(inf)
        signers.sign_pdf(
            pdf_out=w,
            signature_meta=signature_meta,
            signer=signer,
            timestamper=timestamper,
            output=outf,
            existing_fields_only=False
        )
    
    return output_path
