from app import app, db
from models import Document

with app.app_context():
    try:
        docs = Document.query.first()
        if docs:
            print(f"Column already exists: {docs.hash_algorithm}")
        else:
            print("No documents found, but column should exist")
    except:
        import sqlalchemy as sa
        
        engine = db.engine
        conn = engine.connect()
        conn.execute(sa.text("ALTER TABLE document ADD COLUMN hash_algorithm VARCHAR(20) DEFAULT 'sha256'"))
        conn.close()
        print("Added hash_algorithm column to document table")