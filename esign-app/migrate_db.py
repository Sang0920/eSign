from app import app, db
from models import Document

# Run this once to add the new column
with app.app_context():
    # Check if column exists
    try:
        # Try to access the new field on a document
        docs = Document.query.first()
        if docs:
            # Column exists, just print
            print(f"Column already exists: {docs.hash_algorithm}")
        else:
            print("No documents found, but column should exist")
    except:
        # If it fails, the column doesn't exist yet
        import sqlalchemy as sa
        # from sqlalchemy import Column, String
        # from alembic import op
        
        # Manual migration
        engine = db.engine
        conn = engine.connect()
        conn.execute(sa.text("ALTER TABLE document ADD COLUMN hash_algorithm VARCHAR(20) DEFAULT 'sha256'"))
        conn.close()
        print("Added hash_algorithm column to document table")