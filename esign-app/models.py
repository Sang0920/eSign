from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    full_name = db.Column(db.String(120))
    organization = db.Column(db.String(120))
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    has_keys = db.Column(db.Boolean, default=False)
    documents = db.relationship('Document', backref='owner', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

# class Document(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     filename = db.Column(db.String(120), nullable=False)
#     original_filename = db.Column(db.String(120), nullable=False)
#     upload_date = db.Column(db.DateTime, default=datetime.utcnow)
#     signed = db.Column(db.Boolean, default=False)
#     signed_filename = db.Column(db.String(120))
#     sign_date = db.Column(db.DateTime)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
#     def __repr__(self):
#         return f'<Document {self.original_filename}>'

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    original_filename = db.Column(db.String(120), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    signed = db.Column(db.Boolean, default=False)
    signed_filename = db.Column(db.String(120))
    sign_date = db.Column(db.DateTime)
    hash_algorithm = db.Column(db.String(20), default='sha256')  # Added this field
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __repr__(self):
        return f'<Document {self.original_filename}>'
    