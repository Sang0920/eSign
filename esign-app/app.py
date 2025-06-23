import os
import uuid
# import json
from datetime import datetime
from pathlib import Path
from io import BytesIO
import base64
from PIL import Image
import fitz  # PyMuPDF

from flask import Flask, render_template, redirect, url_for, flash, request, session, send_from_directory, jsonify
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.utils import secure_filename

from config import Config
from models import db, User, Document, SavedSignature
from utils.crypto import generate_key_pair
from utils.pdf import add_image_signature_to_pdf, sign_pdf_with_timestamp

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

for folder in [app.config['UPLOAD_FOLDER'], app.config['SIGNATURE_FOLDER'], app.config['KEYS_FOLDER']]:
    Path(folder).mkdir(parents=True, exist_ok=True)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')
        organization = request.form.get('organization')
        
        if not username or not email or not password or not confirm_password or not full_name:
            flash('All fields except organization are required', 'danger')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')
            
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return render_template('register.html')
        
        user = User(username=username, email=email, full_name=full_name, organization=organization)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        try:
            generate_key_pair(user, password, app.config['KEYS_FOLDER'])
            user.has_keys = True
            db.session.commit()
            flash('Account created successfully! You can now log in.', 'success')
        except Exception as e:
            flash(f'Account created but key generation failed: {str(e)}', 'warning')
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = 'remember_me' in request.form
        
        user = User.query.filter_by(username=username).first()
        
        if user is None or not user.check_password(password):
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
        
        login_user(user, remember=remember_me)
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('dashboard')
        
        # Store the password in session for signing PDFs (in real production, use a more secure method)
        session['signing_password'] = password
            
        return redirect(next_page)
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'signing_password' in session:
        session.pop('signing_password')
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', app.config.get('DOCUMENTS_PER_PAGE', 10), type=int)
    search = request.args.get('search', '', type=str)
    status_filter = request.args.get('status', '', type=str)
    
    # Limit per_page to reasonable values
    per_page = min(max(per_page, 5), 100)
    
    # Build query
    query = Document.query.filter_by(user_id=current_user.id)
    
    # Apply search filter
    if search:
        query = query.filter(Document.original_filename.contains(search))
    
    # Apply status filter
    if status_filter == 'signed':
        query = query.filter(Document.signed == True)
    elif status_filter == 'unsigned':
        query = query.filter(Document.signed == False)
    
    documents = query.order_by(Document.upload_date.desc())\
                    .paginate(
                        page=page,
                        per_page=per_page,
                        error_out=False
                    )
    
    return render_template('dashboard.html', documents=documents, search=search, status_filter=status_filter)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'pdf_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('dashboard'))
    
    file = request.files['pdf_file']
    
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('dashboard'))
    
    if file and allowed_file(file.filename):
        # Generate a unique filename
        filename = str(uuid.uuid4()) + '.pdf'
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Save document info to database
        document = Document(
            filename=filename,
            original_filename=secure_filename(file.filename),
            user_id=current_user.id
        )
        db.session.add(document)
        db.session.commit()
        
        flash('File uploaded successfully', 'success')
        return redirect(url_for('sign_document', document_id=document.id))
    
    flash('Invalid file type. Only PDF files are allowed.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/sign/<int:document_id>', methods=['GET', 'POST'])
@login_required
def sign_document(document_id):
    document = Document.query.get_or_404(document_id)
    
    # Check if document belongs to the current user
    if document.user_id != current_user.id:
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Check if using saved signature or new signature
        signature_source = request.form.get('signature_source', 'new')
        
        if signature_source == 'saved':
            signature_id = request.form.get('saved_signature_id')
            if not signature_id:
                flash('Please select a saved signature', 'danger')
                return redirect(url_for('sign_document', document_id=document_id))
            
            # Get the saved signature
            saved_signature = SavedSignature.query.get(signature_id)
            if not saved_signature or saved_signature.user_id != current_user.id:
                flash('Invalid signature selection', 'danger')
                return redirect(url_for('sign_document', document_id=document_id))
            
            # Use the saved signature file
            signature_path = Path(app.config['SIGNATURE_FOLDER']) / saved_signature.filename
        else:
            # Handle new signature (existing code)
            signature_data = request.form.get('signature')
            if not signature_data:
                flash('Signature is required', 'danger')
                return redirect(url_for('sign_document', document_id=document_id))
            
            try:
                # Convert data URL to image and save
                image_data = signature_data.split(',')[1]
                image = Image.open(BytesIO(base64.b64decode(image_data)))
                
                # Save signature image
                signature_filename = f"{current_user.id}_{document_id}_{uuid.uuid4()}.png"
                signature_path = Path(app.config['SIGNATURE_FOLDER']) / signature_filename
                image.save(signature_path)
            except Exception as e:
                flash(f'Error processing signature: {str(e)}', 'danger')
                return redirect(url_for('sign_document', document_id=document_id))
        
        # Get coordinates from form (rest of the existing code remains the same)
        x = float(request.form.get('x', 50))
        y = float(request.form.get('y', 500))
        width = float(request.form.get('width', 200))
        height = float(request.form.get('height', 100))
        page = int(request.form.get('page', 0))
        
        # Get preview dimensions for coordinate conversion
        preview_width = float(request.form.get('preview_width', 800))
        preview_height = float(request.form.get('preview_height', 600))

        # Validate preview dimensions to prevent division by zero
        if preview_width <= 0 or preview_height <= 0:
            flash('Invalid preview dimensions. Please try again.', 'danger')
            return redirect(url_for('sign_document', document_id=document_id))

        # Get selected hash algorithm
        algorithm = request.form.get('algorithm', 'sha256')
        
        # Validate algorithm choice
        valid_algorithms = ['sha256', 'sha384', 'sha512', 'sha3_256', 'sha3_512']
        if algorithm not in valid_algorithms:
            algorithm = 'sha256'  # Default to SHA-256 if invalid selection
            
        try:
            # Path to the uploaded PDF
            pdf_path = Path(app.config['UPLOAD_FOLDER']) / document.filename
            
            # Path for output PDF with signature image
            temp_pdf_path = Path(app.config['UPLOAD_FOLDER']) / f"temp_{document.filename}"
            
            # Open PDF to get actual page dimensions for coordinate conversion
            doc = fitz.open(pdf_path)
            if page >= len(doc):
                flash(f'Selected page {page+1} is out of range', 'danger')
                return redirect(url_for('sign_document', document_id=document_id))
            
            # Get the actual page dimensions
            pdf_page = doc[page]
            actual_page_width = pdf_page.rect.width
            actual_page_height = pdf_page.rect.height
            doc.close()

            # Convert from top-left origin (browser) to bottom-left origin (PDF)
            pdf_x = x
            pdf_y = y
            pdf_width = width
            pdf_height = height

            # Create the coordinate tuple for PDF
            pdf_coordinates = (pdf_x, pdf_y, pdf_x + pdf_width, pdf_y + pdf_height)

            print(f"Debug Backend: Browser coordinates - x={x}, y={y}, w={width}, h={height}")
            print(f"Debug Backend: PDF coordinates - x={pdf_x}, y={pdf_y}, w={pdf_width}, h={pdf_height}")
            print(f"Debug Backend: PDF coordinates tuple - {pdf_coordinates}")
            print(f"Debug Backend: Page {page}, Algorithm {algorithm}")
            print(f"Debug Backend: Actual page dimensions - {actual_page_width}x{actual_page_height}")
            print(f"Debug Backend: Preview dimensions - {preview_width}x{preview_height}")
            
            # Add signature image to PDF
            add_image_signature_to_pdf(pdf_path, signature_path, temp_pdf_path, pdf_coordinates, page)
            
            # Sign the PDF digitally
            signed_filename = f"signed_{document.filename}"
            signed_pdf_path = Path(app.config['UPLOAD_FOLDER']) / signed_filename
            
            # Get user's keys
            key_path = Path(app.config['KEYS_FOLDER']) / str(current_user.id) / 'private_key.pem'
            cert_path = Path(app.config['KEYS_FOLDER']) / str(current_user.id) / 'certificate.pem'
            
            # Check if keys exist
            if not key_path.exists() or not cert_path.exists():
                flash('Digital certificate not found. Please contact support.', 'danger')
                return redirect(url_for('dashboard'))
            
            # Signature metadata with selected algorithm
            metadata = {
                'field_name': 'Signature1',
                'reason': 'I approve this document',
                'location': 'Ho Chi Minh City, VN',
                'contact_info': current_user.email,
                'md_algorithm': algorithm
            }
            
            # Sign the PDF
            if 'signing_password' not in session:
                flash('Session expired. Please log in again.', 'danger')
                return redirect(url_for('login'))
            
            try:
                sign_pdf_with_timestamp(
                    temp_pdf_path,
                    signed_pdf_path,
                    cert_path,
                    key_path,
                    session['signing_password'],
                    app.config['TSA_URL'],
                    metadata
                )
                
                # Update document record with algorithm info
                document.signed = True
                document.signed_filename = signed_filename
                document.sign_date = datetime.utcnow()
                
                # Store the algorithm used
                if hasattr(document, 'hash_algorithm'):
                    document.hash_algorithm = algorithm
                    
                db.session.commit()
                
                # Clean up temp file
                if temp_pdf_path.exists():
                    os.remove(temp_pdf_path)
                
                flash(f'Document signed successfully using {algorithm.upper()}', 'success')
                return redirect(url_for('view_document', document_id=document.id))
                
            except Exception as e:
                flash(f'Error signing document: {str(e)}', 'danger')
                return redirect(url_for('dashboard'))
                
        except Exception as e:
            flash(f'Error processing signature: {str(e)}', 'danger')
            return redirect(url_for('sign_document', document_id=document_id))
    
    # GET request - render the signing page with saved signatures
    saved_signatures = SavedSignature.query.filter_by(user_id=current_user.id).order_by(SavedSignature.is_default.desc(), SavedSignature.created_date.desc()).all()
    return render_template('sign_pdf.html', document=document, saved_signatures=saved_signatures)

@app.route('/view_file/<int:document_id>')
@login_required
def view_file(document_id):
    document = Document.query.get_or_404(document_id)
    
    # Check if document belongs to the current user
    if document.user_id != current_user.id:
        return "Document not found", 404
    
    filename = document.signed_filename if document.signed else document.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        return "File not found", 404
    
    # Serve the file without forcing download
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=False
    )

@app.route('/view/<int:document_id>')
@login_required
def view_document(document_id):
    document = Document.query.get_or_404(document_id)
    
    # Check if document belongs to the current user
    if document.user_id != current_user.id:
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    filename = document.signed_filename if document.signed else document.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        flash(f'File not found at {file_path}. Please check if the file exists.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Add debug information
    file_info = {
        'exists': os.path.exists(file_path),
        'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
        'path': file_path
    }
    
    return render_template('view_pdf.html', document=document, file_info=file_info)

@app.route('/download/<int:document_id>')
@login_required
def download_document(document_id):
    document = Document.query.get_or_404(document_id)
    
    # Check if document belongs to the current user
    if document.user_id != current_user.id:
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    filename = document.signed_filename if document.signed else document.filename
    display_name = f"signed_{document.original_filename}" if document.signed else document.original_filename
    
    # Check if this is a download request or embedded viewing
    as_attachment = request.args.get('download', 'true').lower() == 'true'
    
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=as_attachment,
        download_name=display_name if as_attachment else None
    )

@app.route('/preview/<int:document_id>')
@login_required
def preview_document(document_id):
    document = Document.query.get_or_404(document_id)
    
    # Check if document belongs to the current user
    if document.user_id != current_user.id:
        return jsonify({'error': 'Document not found'}), 404
    
    filename = document.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    # Extract basic PDF info
    try:
        doc = fitz.open(file_path)
        info = {
            'pageCount': len(doc),
            'title': doc.metadata.get('title', ''),
            'author': doc.metadata.get('author', ''),
            'pages': []
        }
        
        # Get first page thumbnail for preview
        first_page = doc[0]
        pix = first_page.get_pixmap(matrix=fitz.Matrix(0.2, 0.2))
        img_data = pix.tobytes("png")
        img_base64 = base64.b64encode(img_data).decode('utf-8')
        info['thumbnail'] = f"data:image/png;base64,{img_base64}"
        
        doc.close()
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_page/<int:document_id>')
@login_required
def get_page_image(document_id):
    page_num = request.args.get('page_num', 0, type=int)
    document = Document.query.get_or_404(document_id)
    
    # Check if document belongs to the current user
    if document.user_id != current_user.id:
        return jsonify({'error': 'Document not found'}), 404
    
    filename = document.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        doc = fitz.open(file_path)
        if page_num >= len(doc):
            return jsonify({'error': 'Page out of range'}), 404
        
        page = doc[page_num]
        pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))  # Scale factor for higher resolution
        img_data = pix.tobytes("png")
        img_base64 = base64.b64encode(img_data).decode('utf-8')
        
        # Get page dimensions
        width, height = page.rect.width, page.rect.height
        
        doc.close()
        return jsonify({
            'image': f"data:image/png;base64,{img_base64}",
            'width': width,
            'height': height
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/signatures')
@login_required
def manage_signatures():
    signatures = SavedSignature.query.filter_by(user_id=current_user.id).order_by(SavedSignature.created_date.desc()).all()
    return render_template('manage_signatures.html', signatures=signatures)

@app.route('/signatures/create', methods=['GET', 'POST'])
@login_required
def create_signature():
    if request.method == 'POST':
        signature_data = request.form.get('signature')
        signature_name = request.form.get('name', '').strip()
        is_default = 'is_default' in request.form
        
        if not signature_data:
            flash('Signature is required', 'danger')
            return redirect(url_for('create_signature'))
        
        if not signature_name:
            flash('Signature name is required', 'danger')
            return redirect(url_for('create_signature'))
        
        # Check if name already exists for this user
        existing = SavedSignature.query.filter_by(user_id=current_user.id, name=signature_name).first()
        if existing:
            flash('A signature with this name already exists', 'danger')
            return redirect(url_for('create_signature'))
        
        try:
            # Convert data URL to image and save
            image_data = signature_data.split(',')[1]
            image = Image.open(BytesIO(base64.b64decode(image_data)))
            
            # Save signature image
            signature_filename = f"signature_{current_user.id}_{uuid.uuid4()}.png"
            signature_path = Path(app.config['SIGNATURE_FOLDER']) / signature_filename
            image.save(signature_path)
            
            # If this is set as default, remove default from other signatures
            if is_default:
                SavedSignature.query.filter_by(user_id=current_user.id, is_default=True).update({'is_default': False})
            
            # Save to database
            saved_signature = SavedSignature(
                name=signature_name,
                filename=signature_filename,
                user_id=current_user.id,
                is_default=is_default
            )
            db.session.add(saved_signature)
            db.session.commit()
            
            flash('Signature saved successfully!', 'success')
            return redirect(url_for('manage_signatures'))
            
        except Exception as e:
            flash(f'Error saving signature: {str(e)}', 'danger')
            return redirect(url_for('create_signature'))
    
    return render_template('create_signature.html')

@app.route('/signatures/delete/<int:signature_id>', methods=['POST'])
@login_required
def delete_signature(signature_id):
    signature = SavedSignature.query.get_or_404(signature_id)
    
    # Check if signature belongs to the current user
    if signature.user_id != current_user.id:
        flash('Signature not found', 'danger')
        return redirect(url_for('manage_signatures'))
    
    try:
        # Delete the file
        signature_path = Path(app.config['SIGNATURE_FOLDER']) / signature.filename
        if signature_path.exists():
            os.remove(signature_path)
        
        # Delete from database
        db.session.delete(signature)
        db.session.commit()
        
        flash('Signature deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting signature: {str(e)}', 'danger')
    
    return redirect(url_for('manage_signatures'))

@app.route('/signatures/set_default/<int:signature_id>', methods=['POST'])
@login_required
def set_default_signature(signature_id):
    signature = SavedSignature.query.get_or_404(signature_id)
    
    # Check if signature belongs to the current user
    if signature.user_id != current_user.id:
        flash('Signature not found', 'danger')
        return redirect(url_for('manage_signatures'))
    
    try:
        # Remove default from all signatures for this user
        SavedSignature.query.filter_by(user_id=current_user.id, is_default=True).update({'is_default': False})
        
        # Set this signature as default
        signature.is_default = True
        db.session.commit()
        
        flash('Default signature updated!', 'success')
    except Exception as e:
        flash(f'Error updating default signature: {str(e)}', 'danger')
    
    return redirect(url_for('manage_signatures'))

@app.route('/signatures/get/<int:signature_id>')
@login_required
def get_signature(signature_id):
    signature = SavedSignature.query.get_or_404(signature_id)
    
    # Check if signature belongs to the current user
    if signature.user_id != current_user.id:
        return jsonify({'error': 'Signature not found'}), 404
    
    signature_path = Path(app.config['SIGNATURE_FOLDER']) / signature.filename
    
    if not signature_path.exists():
        return jsonify({'error': 'Signature file not found'}), 404
    
    try:
        with open(signature_path, 'rb') as f:
            img_data = f.read()
        
        img_base64 = base64.b64encode(img_data).decode('utf-8')
        return jsonify({
            'image': f"data:image/png;base64,{img_base64}",
            'name': signature.name
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/signature_image/<filename>')
@login_required
def get_signature_image(filename):
    """Serve signature images securely"""
    # Check if the signature belongs to the current user
    signature = SavedSignature.query.filter_by(filename=filename, user_id=current_user.id).first()
    if not signature:
        return "Image not found", 404
    
    signature_path = Path(app.config['SIGNATURE_FOLDER']) / filename
    if not signature_path.exists():
        return "Image not found", 404
    
    return send_from_directory(
        app.config['SIGNATURE_FOLDER'],
        filename,
        as_attachment=False
    )

@app.route('/delete/<int:document_id>', methods=['POST'])
@login_required
def delete_document(document_id):
    document = Document.query.get_or_404(document_id)
    
    # Check if document belongs to the current user
    if document.user_id != current_user.id:
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Delete the original file
        if document.filename:
            original_file_path = Path(app.config['UPLOAD_FOLDER']) / document.filename
            if original_file_path.exists():
                os.remove(original_file_path)
        
        # Delete the signed file if it exists
        if document.signed and document.signed_filename:
            signed_file_path = Path(app.config['UPLOAD_FOLDER']) / document.signed_filename
            if signed_file_path.exists():
                os.remove(signed_file_path)
        
        # Delete from database
        db.session.delete(document)
        db.session.commit()
        
        flash('Document deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting document: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

# Initialize database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)