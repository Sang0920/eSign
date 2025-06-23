from models import db, SavedSignature
from app import app

with app.app_context():
    db.create_all()
    print("Database updated with SavedSignature table")