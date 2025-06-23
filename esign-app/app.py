import os
import uuid
from datetime import datetime
from pathlib import Path
from io import BytesIO
import base64
from venv import logger
from PIL import Image
import click
import fitz  # PyMuPDF

from flask import Flask, render_template, redirect, url_for, flash, request, session, send_from_directory, jsonify
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.utils import secure_filename

from config import Config
from models import db, User, Document, SavedSignature, CertificateValidation, KeyRotationHistory
from utils.crypto import generate_key_pair
from utils.pdf import add_image_signature_to_pdf, sign_pdf_with_timestamp
from utils.security import password_manager
from utils.certificate_validation import certificate_validator
from utils.key_rotation import key_rotation_manager

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

for folder in [app.config['UPLOAD_FOLDER'], app.config['SIGNATURE_FOLDER'], app.config['KEYS_FOLDER']]:
    Path(folder).mkdir(parents=True, exist_ok=True)

@login_manager.user_loader
def load_user(id):
    from sqlalchemy.orm import sessionmaker
    return db.session.get(User, int(id))

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
        
        auth_token = password_manager.store_password_temporarily(password, user.id)
        session['auth_token'] = auth_token
            
        return redirect(next_page)
    
    return render_template('login.html')

@app.route('/confirm_password', methods=['POST'])
@login_required
def confirm_password():
    """Endpoint for re-authentication before critical operations"""
    password = request.form.get('password')
    operation = request.form.get('operation')
    document_id = request.form.get('document_id')
    
    if not current_user.check_password(password):
        logger.warning(f"Invalid password attempt for user {current_user.id}")
        return jsonify({'success': False, 'error': 'Invalid password'})
    
    try:
        auth_token = password_manager.store_password_temporarily(password, current_user.id)
        
        # Also store in session as backup
        session['auth_token'] = auth_token
        session.permanent = True
        
        logger.info(f"Successfully created auth session for user {current_user.id}")
        
        return jsonify({
            'success': True, 
            'auth_token': auth_token,
            'redirect_url': url_for('sign_document', document_id=document_id) if operation == 'sign' else None
        })
        
    except Exception as e:
        logger.error(f"Failed to create auth session for user {current_user.id}: {e}")
        return jsonify({'success': False, 'error': 'Failed to create authentication session'})

@app.route('/logout')
def logout():
    password_manager.clear_password_session()
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', app.config.get('DOCUMENTS_PER_PAGE', 10), type=int)
    search = request.args.get('search', '', type=str)
    status_filter = request.args.get('status', '', type=str)
    
    per_page = min(max(per_page, 5), 100)
    
    query = Document.query.filter_by(user_id=current_user.id)
    
    if search:
        query = query.filter(Document.original_filename.contains(search))
    
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
        filename = str(uuid.uuid4()) + '.pdf'
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
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
    
    if document.user_id != current_user.id:
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Try multiple sources for auth token
        auth_token = (
            request.form.get('auth_token') or 
            request.headers.get('X-Auth-Token') or
            session.get('auth_token')
        )
        
        if not auth_token:
            logger.warning(f"No auth token found for user {current_user.id} signing document {document_id}")
            flash('Authentication required for signing. Please verify your password.', 'warning')
            return redirect(url_for('require_reauth', document_id=document_id, operation='sign'))
        
        try:
            signing_password = password_manager.retrieve_password(auth_token, current_user.id)
            password_manager.extend_session(auth_token, current_user.id)
        except ValueError as e:
            logger.warning(f"Authentication error for user {current_user.id}: {str(e)}")
            # Clear any stale sessions
            password_manager.clear_password_session()
            flash(f'Authentication error: {str(e)}. Please verify your password again.', 'warning')
            return redirect(url_for('require_reauth', document_id=document_id, operation='sign'))
        
        signature_source = request.form.get('signature_source', 'new')
        
        if signature_source == 'saved':
            signature_id = request.form.get('saved_signature_id')
            if not signature_id:
                flash('Please select a saved signature', 'danger')
                return redirect(url_for('sign_document', document_id=document_id))
            
            saved_signature = SavedSignature.query.get(signature_id)
            if not saved_signature or saved_signature.user_id != current_user.id:
                flash('Invalid signature selection', 'danger')
                return redirect(url_for('sign_document', document_id=document_id))
            
            signature_path = Path(app.config['SIGNATURE_FOLDER']) / saved_signature.filename
        else:
            signature_data = request.form.get('signature')
            if not signature_data:
                flash('Signature is required', 'danger')
                return redirect(url_for('sign_document', document_id=document_id))
            
            try:
                image_data = signature_data.split(',')[1]
                image = Image.open(BytesIO(base64.b64decode(image_data)))
                
                signature_filename = f"{current_user.id}_{document_id}_{uuid.uuid4()}.png"
                signature_path = Path(app.config['SIGNATURE_FOLDER']) / signature_filename
                image.save(signature_path)
            except Exception as e:
                flash(f'Error processing signature: {str(e)}', 'danger')
                return redirect(url_for('sign_document', document_id=document_id))
        
        x = float(request.form.get('x', 50))
        y = float(request.form.get('y', 500))
        width = float(request.form.get('width', 200))
        height = float(request.form.get('height', 100))
        page = int(request.form.get('page', 0))
        
        preview_width = float(request.form.get('preview_width', 800))
        preview_height = float(request.form.get('preview_height', 600))

        if preview_width <= 0 or preview_height <= 0:
            flash('Invalid preview dimensions. Please try again.', 'danger')
            return redirect(url_for('sign_document', document_id=document_id))
        
        algorithm = request.form.get('algorithm', 'sha256')
        
        valid_algorithms = ['sha256', 'sha384', 'sha512', 'sha3_256', 'sha3_512']
        if algorithm not in valid_algorithms:
            algorithm = 'sha256'  # Default to SHA-256 if invalid selection
            
        try:
            pdf_path = Path(app.config['UPLOAD_FOLDER']) / document.filename
            
            temp_pdf_path = Path(app.config['UPLOAD_FOLDER']) / f"temp_{document.filename}"
            
            doc = fitz.open(pdf_path)
            if page >= len(doc):
                flash(f'Selected page {page+1} is out of range', 'danger')
                return redirect(url_for('sign_document', document_id=document_id))
            
            pdf_page = doc[page]
            actual_page_width = pdf_page.rect.width
            actual_page_height = pdf_page.rect.height
            doc.close()

            pdf_x = x
            pdf_y = y
            pdf_width = width
            pdf_height = height

            pdf_coordinates = (pdf_x, pdf_y, pdf_x + pdf_width, pdf_y + pdf_height)
            
            add_image_signature_to_pdf(pdf_path, signature_path, temp_pdf_path, pdf_coordinates, page)
            
            signed_filename = f"signed_{document.filename}"
            signed_pdf_path = Path(app.config['UPLOAD_FOLDER']) / signed_filename
            
            key_path = Path(app.config['KEYS_FOLDER']) / str(current_user.id) / 'private_key.pem'
            cert_path = Path(app.config['KEYS_FOLDER']) / str(current_user.id) / 'certificate.pem'
            
            if not key_path.exists() or not cert_path.exists():
                flash('Digital certificate not found. Please contact support.', 'danger')
                return redirect(url_for('dashboard'))
            
            metadata = {
                'field_name': 'Signature1',
                'reason': 'I approve this document',
                'location': 'Ho Chi Minh City, VN',
                'contact_info': current_user.email,
                'md_algorithm': algorithm
            }
            
            try:
                sign_pdf_with_timestamp(
                    temp_pdf_path,
                    signed_pdf_path,
                    cert_path,
                    key_path,
                    signing_password,  # Use the securely retrieved password
                    app.config['TSA_URL'],
                    metadata
                )
                
                document.signed = True
                document.signed_filename = signed_filename
                document.sign_date = datetime.utcnow()
                
                if hasattr(document, 'hash_algorithm'):
                    document.hash_algorithm = algorithm
                    
                db.session.commit()
                
                if temp_pdf_path.exists():
                    os.remove(temp_pdf_path)
                
                # Clear the password session after successful signing
                password_manager.clear_password_session(auth_token)
                
                flash(f'Document signed successfully using {algorithm.upper()}', 'success')
                return redirect(url_for('view_document', document_id=document.id))
                
            except Exception as e:
                logger.error(f"Error signing document {document_id} for user {current_user.id}: {e}")
                flash(f'Error signing document: {str(e)}', 'danger')
                return redirect(url_for('dashboard'))
                
        except Exception as e:
            logger.error(f"Error processing signature for document {document_id}: {e}")
            flash(f'Error processing signature: {str(e)}', 'danger')
            return redirect(url_for('sign_document', document_id=document_id))
    
    saved_signatures = SavedSignature.query.filter_by(user_id=current_user.id).order_by(SavedSignature.is_default.desc(), SavedSignature.created_date.desc()).all()
    return render_template('sign_pdf.html', document=document, saved_signatures=saved_signatures)

@app.route('/reauth/<int:document_id>/<operation>')
@login_required
def require_reauth(document_id, operation):
    """Require re-authentication for sensitive operations"""
    document = Document.query.get_or_404(document_id)
    
    if document.user_id != current_user.id:
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('reauth.html', document=document, operation=operation)

@app.route('/view_file/<int:document_id>')
@login_required
def view_file(document_id):
    document = Document.query.get_or_404(document_id)
    
    if document.user_id != current_user.id:
        return "Document not found", 404
    
    filename = document.signed_filename if document.signed else document.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        return "File not found", 404
    
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=False
    )

@app.route('/view/<int:document_id>')
@login_required
def view_document(document_id):
    document = Document.query.get_or_404(document_id)
    
    if document.user_id != current_user.id:
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    filename = document.signed_filename if document.signed else document.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        flash(f'File not found at {file_path}. Please check if the file exists.', 'danger')
        return redirect(url_for('dashboard'))
    
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
    
    if document.user_id != current_user.id:
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    filename = document.signed_filename if document.signed else document.filename
    display_name = f"signed_{document.original_filename}" if document.signed else document.original_filename
    
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
    
    if document.user_id != current_user.id:
        return jsonify({'error': 'Document not found'}), 404
    
    filename = document.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        doc = fitz.open(file_path)
        info = {
            'pageCount': len(doc),
            'title': doc.metadata.get('title', ''),
            'author': doc.metadata.get('author', ''),
            'pages': []
        }
        
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
        
        existing = SavedSignature.query.filter_by(user_id=current_user.id, name=signature_name).first()
        if existing:
            flash('A signature with this name already exists', 'danger')
            return redirect(url_for('create_signature'))
        
        try:
            image_data = signature_data.split(',')[1]
            image = Image.open(BytesIO(base64.b64decode(image_data)))
            
            signature_filename = f"signature_{current_user.id}_{uuid.uuid4()}.png"
            signature_path = Path(app.config['SIGNATURE_FOLDER']) / signature_filename
            image.save(signature_path)
            
            if is_default:
                SavedSignature.query.filter_by(user_id=current_user.id, is_default=True).update({'is_default': False})
            
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
    
    if signature.user_id != current_user.id:
        flash('Signature not found', 'danger')
        return redirect(url_for('manage_signatures'))
    
    try:
        signature_path = Path(app.config['SIGNATURE_FOLDER']) / signature.filename
        if signature_path.exists():
            os.remove(signature_path)
        
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
    
    if signature.user_id != current_user.id:
        flash('Signature not found', 'danger')
        return redirect(url_for('manage_signatures'))
    
    try:
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
    
    if document.user_id != current_user.id:
        flash('Document not found', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        if document.filename:
            original_file_path = Path(app.config['UPLOAD_FOLDER']) / document.filename
            if original_file_path.exists():
                os.remove(original_file_path)
        
        if document.signed and document.signed_filename:
            signed_file_path = Path(app.config['UPLOAD_FOLDER']) / document.signed_filename
            if signed_file_path.exists():
                os.remove(signed_file_path)
        
        db.session.delete(document)
        db.session.commit()
        
        flash('Document deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting document: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/certificate/validate')
@login_required
def validate_certificate():
    """Validate current user's certificate"""
    user_keys_folder = Path(app.config['KEYS_FOLDER']) / str(current_user.id)
    cert_path = user_keys_folder / 'certificate.pem'
    
    if not cert_path.exists():
        flash('No certificate found. Please contact administrator.', 'danger')
        return redirect(url_for('dashboard'))
    
    validation_result = certificate_validator.validate_certificate_chain(cert_path)
    
    cert_validation = CertificateValidation(
        user_id=current_user.id,
        validation_status='valid' if validation_result['valid'] else 'invalid',
        validation_details=validation_result,
        certificate_serial=validation_result.get('certificate_info', {}).get('serial_number'),
        expires_on=datetime.fromisoformat(validation_result.get('certificate_info', {}).get('not_after', '1970-01-01T00:00:00')) if validation_result.get('certificate_info', {}).get('not_after') else None
    )
    db.session.add(cert_validation)
    
    current_user.certificate_validation_status = 'valid' if validation_result['valid'] else 'invalid'
    current_user.last_certificate_check = datetime.utcnow()
    if cert_validation.expires_on:
        current_user.certificate_expiry_date = cert_validation.expires_on
    
    db.session.commit()
    
    return render_template('certificate_validation.html', 
                         validation_result=validation_result,
                         cert_validation=cert_validation)

@app.route('/certificate/rotation-check')
@login_required
def check_key_rotation():
    """Check if user's keys need rotation"""
    rotation_check = key_rotation_manager.should_rotate_keys(current_user.id)
    
    return render_template('key_rotation_check.html', 
                         rotation_check=rotation_check,
                         user=current_user)

@app.route('/certificate/rotate', methods=['GET', 'POST'])
@login_required
def rotate_keys():
    """Rotate user's keys and certificate"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_password:
            flash('Current password is required', 'danger')
            return redirect(url_for('rotate_keys'))
        
        if new_password and new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('rotate_keys'))
        
        rotation_result = key_rotation_manager.rotate_user_keys(
            current_user.id, 
            current_password, 
            new_password if new_password else current_password
        )
        
        if rotation_result['success']:
            rotation_history = KeyRotationHistory(
                user_id=current_user.id,
                rotation_reason='User initiated rotation',
                initiated_by='user',
                backup_path=str(rotation_result['backup_path'])
            )
            db.session.add(rotation_history)
            
            if new_password:
                current_user.set_password(new_password)
            
            current_user.key_rotation_reminder_sent = False
            db.session.commit()
            
            flash('Keys rotated successfully! Please log in again.', 'success')
            logout_user()
            return redirect(url_for('login'))
        else:
            flash(f'Key rotation failed: {rotation_result["error"]}', 'danger')
            return redirect(url_for('rotate_keys'))
    
    rotation_check = key_rotation_manager.should_rotate_keys(current_user.id)
    
    return render_template('key_rotation.html', 
                         rotation_check=rotation_check)

@app.route('/admin/certificate-status')
@login_required
def admin_certificate_status():
    """Admin view of all users' certificate status"""
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    certificate_status = []
    
    for user in users:
        rotation_check = key_rotation_manager.should_rotate_keys(user.id)
        
        certificate_status.append({
            'user': user,
            'rotation_check': rotation_check,
            'last_validation': user.last_certificate_check,
            'status': user.certificate_validation_status,
            'expiry': user.certificate_expiry_date
        })
    
    return render_template('admin_certificate_status.html', 
                         certificate_status=certificate_status)

@app.cli.command()
def check_certificate_expiry():
    """CLI command to check certificate expiry for all users"""
    click.echo('Checking certificate expiry for all users...')
    
    users = User.query.all()
    expiring_soon = []
    expired = []
    
    for user in users:
        rotation_check = key_rotation_manager.should_rotate_keys(user.id)
        
        if rotation_check['urgency'] == 'critical':
            expired.append((user, rotation_check))
        elif rotation_check['urgency'] in ['high', 'medium']:
            expiring_soon.append((user, rotation_check))
    
    click.echo(f'Found {len(expired)} expired certificates')
    click.echo(f'Found {len(expiring_soon)} certificates expiring soon')
    
    # send_expiry_notifications(expired, expiring_soon)
    
    return {'expired': len(expired), 'expiring_soon': len(expiring_soon)}

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
