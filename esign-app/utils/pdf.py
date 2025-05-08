import io
import os
import fitz  # PyMuPDF
import datetime
from pathlib import Path
from PIL import Image
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, timestamps
from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
from pyhanko.sign.signers import PdfSignatureMetadata

def add_image_signature_to_pdf(input_path, image_path, output_path, browser_coordinates, page_num=0):
    """
    Add a signature image to a PDF file with proper coordinate conversion
    
    browser_coordinates: tuple of (x1, y1, x2, y2) in browser coordinate space
    """
    # Open the PDF
    doc = fitz.open(input_path)
    
    # Get the page
    if page_num >= len(doc):
        raise ValueError(f"Page number {page_num} out of range.")
    page = doc[page_num]
    
    # Get the page dimensions
    page_width, page_height = page.rect.width, page.rect.height
    
    # Extract browser coordinates
    x1, y1, x2, y2 = browser_coordinates
    
    # Calculate the image dimensions
    img_width = x2 - x1
    img_height = y2 - y1
    
    # Create a pixmap from the image to get its dimensions
    img_pix = fitz.Pixmap(image_path)
    sig_width, sig_height = img_pix.width, img_pix.height
    
    # Create a temporary image with proper resolution for PDF
    # (this ensures better quality and positioning)
    tmp_img_path = image_path.parent / f"tmp_{image_path.name}"
    img = Image.open(image_path)
    img = img.resize((int(img_width * 2), int(img_height * 2)), Image.LANCZOS)
    img.save(tmp_img_path)
    
    # Insert the image at the correct position
    try:
        # Create rectangle for the image - convert browser coordinates to PDF coordinates
        rect = fitz.Rect(x1, y1, x2, y2)
        
        # Insert the image
        page.insert_image(rect, filename=str(tmp_img_path))
        
        # Clean up temporary image
        os.remove(tmp_img_path)
    except Exception as e:
        if os.path.exists(tmp_img_path):
            os.remove(tmp_img_path)
        raise ValueError(f"Error inserting image: {str(e)}")
    
    # Save the PDF
    doc.save(output_path)
    doc.close()
    
    return output_path

# def sign_pdf_with_timestamp(
#     input_path,
#     output_path,
#     cert_path,
#     key_path,
#     key_passphrase,
#     tsa_url,
#     metadata
# ):
#     """Sign a PDF with digital signature and timestamp"""
#     # Load signer credentials
#     signer = signers.SimpleSigner.load(
#         key_file=str(key_path),
#         cert_file=str(cert_path),
#         key_passphrase=key_passphrase.encode('utf-8')
#     )
    
#     # Create timestamp client
#     timestamper = None
#     if tsa_url:
#         timestamper = timestamps.HTTPTimeStamper(tsa_url)
    
#     # Create signature metadata
#     signature_meta = PdfSignatureMetadata(
#         field_name=metadata.get('field_name', 'Signature1'),
#         reason=metadata.get('reason', 'I approve this document'),
#         location=metadata.get('location', 'Ho Chi Minh City, VN'),
#         contact_info=metadata.get('contact_info', ''),
#         subfilter=SigSeedSubFilter.PADES,
#         md_algorithm='sha256'
#     )
    
#     # Sign the PDF
#     with open(input_path, 'rb') as inf, open(output_path, 'wb') as outf:
#         w = IncrementalPdfFileWriter(inf)
#         signers.sign_pdf(
#             pdf_out=w,
#             signature_meta=signature_meta,
#             signer=signer,
#             timestamper=timestamper,
#             output=outf,
#             existing_fields_only=False
#         )
    
#     return output_path

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
    # Load signer credentials
    signer = signers.SimpleSigner.load(
        key_file=str(key_path),
        cert_file=str(cert_path),
        key_passphrase=key_passphrase.encode('utf-8')
    )
    
    # Create timestamp client
    timestamper = None
    if tsa_url:
        timestamper = timestamps.HTTPTimeStamper(tsa_url)
    
    # Get algorithm from metadata or default to sha256
    md_algorithm = metadata.get('md_algorithm', 'sha256')
    
    # Create signature metadata
    signature_meta = PdfSignatureMetadata(
        field_name=metadata.get('field_name', 'Signature1'),
        reason=metadata.get('reason', 'I approve this document'),
        location=metadata.get('location', 'Ho Chi Minh City, VN'),
        contact_info=metadata.get('contact_info', ''),
        subfilter=SigSeedSubFilter.PADES,
        md_algorithm=md_algorithm
    )
    
    # Sign the PDF
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
