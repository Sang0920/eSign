from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    full_name = db.Column(db.String(120))
    organization = db.Column(db.String(120))
    registration_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    has_keys = db.Column(db.Boolean, default=False)
    documents = db.relationship('Document', backref='owner', lazy='dynamic')

    key_rotation_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    certificate_expiry_date = db.Column(db.DateTime)
    key_rotation_reminder_sent = db.Column(db.Boolean, default=False)
    certificate_validation_status = db.Column(db.String(20), default='unknown')
    last_certificate_check = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class CertificateValidation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    validation_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    validation_status = db.Column(db.String(20), nullable=False)
    validation_details = db.Column(db.JSON)
    certificate_serial = db.Column(db.String(100))
    expires_on = db.Column(db.DateTime)
    
    user = db.relationship('User', backref=db.backref('certificate_validations', lazy=True))

class KeyRotationHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rotation_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    rotation_reason = db.Column(db.String(200))
    old_certificate_serial = db.Column(db.String(100))
    new_certificate_serial = db.Column(db.String(100))
    initiated_by = db.Column(db.String(50))
    backup_path = db.Column(db.String(500))
    
    user = db.relationship('User', backref=db.backref('key_rotations', lazy=True))

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    original_filename = db.Column(db.String(120), nullable=False)
    upload_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    signed = db.Column(db.Boolean, default=False)
    signed_filename = db.Column(db.String(120))
    sign_date = db.Column(db.DateTime)
    hash_algorithm = db.Column(db.String(20), default='sha256')  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __repr__(self):
        return f'<Document {self.original_filename}>'

class SavedSignature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    filename = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_default = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<SavedSignature {self.name}>'
