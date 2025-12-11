"""
Database migration script for risk-based authentication system
Adds new tables to existing database without dropping data
"""

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"

def migrate_database():
    """Add new security tables to existing database"""
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Add new columns to users table if they don't exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'last_login_ip' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN last_login_ip TEXT")
            print("✓ Added last_login_ip column")
        
        if 'last_login_time' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN last_login_time TEXT")
            print("✓ Added last_login_time column")
        
        if 'last_known_fingerprint' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN last_known_fingerprint TEXT")
            print("✓ Added last_known_fingerprint column")
        
        # Create device_fingerprints table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                device_name TEXT,
                browser TEXT,
                os TEXT,
                ip_address TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                is_trusted INTEGER DEFAULT 0,
                trust_expires_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        print("✓ Created device_fingerprints table")
        
        # Create login_attempts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT NOT NULL,
                fingerprint TEXT,
                ip_address TEXT NOT NULL,
                browser TEXT,
                os TEXT,
                success INTEGER NOT NULL,
                risk_score REAL DEFAULT 0.0,
                risk_factors TEXT,
                jwt_token TEXT,
                timestamp TEXT NOT NULL,
                challenge_type TEXT,
                challenge_passed INTEGER DEFAULT NULL
            )
        """)
        print("✓ Created login_attempts table")
        
        # Create security_logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT NOT NULL,
                event_type TEXT NOT NULL,
                risk_level TEXT,
                ip_address TEXT,
                fingerprint TEXT,
                details TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        print("✓ Created security_logs table")
        
        # Create indices for better query performance
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_device_fingerprints_user_fp 
            ON device_fingerprints(user_id, fingerprint)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_login_attempts_user_timestamp 
            ON login_attempts(user_id, timestamp)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_logs_user_timestamp 
            ON security_logs(user_id, timestamp)
        """)
        
        print("✓ Created database indices")
        
        conn.commit()
        print("\n✅ Database migration completed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Migration error: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


if __name__ == "__main__":
    print("🔄 Starting database migration...\n")
    success = migrate_database()
    if not success:
        exit(1)
