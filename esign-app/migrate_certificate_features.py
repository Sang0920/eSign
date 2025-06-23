from app import app, db
from models import User, CertificateValidation, KeyRotationHistory
import sqlalchemy as sa
from datetime import datetime, timezone

def migrate_database():
    """Add new columns for certificate validation and key rotation features"""
    
    with app.app_context():
        try:
            engine = db.engine
            conn = engine.connect()
            
            new_user_columns = [
                ('key_rotation_date', 'DATETIME', f"'{datetime.now(timezone.utc).isoformat()}'"),
                ('certificate_expiry_date', 'DATETIME', 'NULL'),
                ('key_rotation_reminder_sent', 'BOOLEAN', 'FALSE'),
                ('certificate_validation_status', 'VARCHAR(20)', "'unknown'"),
                ('last_certificate_check', 'DATETIME', 'NULL'),
                ('is_admin', 'BOOLEAN', 'FALSE')
            ]
            
            result = conn.execute(sa.text("PRAGMA table_info(user)"))
            existing_columns = [row[1] for row in result.fetchall()]
            print(f"Existing columns: {existing_columns}")
            
            for column_name, column_type, default_value in new_user_columns:
                if column_name not in existing_columns:
                    try:
                        sql = f"ALTER TABLE user ADD COLUMN {column_name} {column_type} DEFAULT {default_value}"
                        print(f"Executing: {sql}")
                        conn.execute(sa.text(sql))
                        conn.commit()
                        print(f"✓ Added column: {column_name}")
                    except Exception as e:
                        print(f"✗ Error adding column {column_name}: {e}")
                else:
                    print(f"✓ Column {column_name} already exists")
            
            conn.close()
            
            print("Creating new tables...")
            db.create_all()
            print("✓ New tables created successfully!")
            
            print("✓ Database migration completed successfully!")
            
        except Exception as e:
            print(f"✗ Migration failed: {e}")
            return False
            
    return True

if __name__ == '__main__':
    print("Starting database migration...")
    migrate_database()