#!/usr/bin/env python3
"""
Safe Database Reinitialization with Confirmation
Prevents accidental data loss by requiring confirmation.
"""

import sys
from pathlib import Path
from datetime import datetime
import shutil
import sqlite3

DB_PATH = Path(__file__).parent / "app.db"
SQL_PATH = Path(__file__).parent / "init_db.sql"

def get_doctor_count():
    """Get number of doctors in database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'doctor'")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except:
        return 0

def get_user_count():
    """Get total number of users in database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except:
        return 0

def get_doctor_names():
    """Get list of doctor names"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT username, email FROM users WHERE role = 'doctor'")
        doctors = cursor.fetchall()
        conn.close()
        return [(d['username'], d['email']) for d in doctors]
    except:
        return []

def reinitialize_database():
    """Reinitialize database from SQL file"""
    # Create backup
    if DB_PATH.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = DB_PATH.parent / f"app_backup_{timestamp}.db"
        shutil.copy2(DB_PATH, backup_path)
        print(f"✓ Backup created: {backup_path}")
    
    # Reinitialize
    try:
        conn = sqlite3.connect(DB_PATH)
        with open(SQL_PATH) as f:
            sql_script = f.read()
        conn.executescript(sql_script)
        conn.close()
        print("✓ Database reinitialized successfully")
        return True
    except Exception as e:
        print(f"❌ Error reinitializing database: {e}")
        return False

def main():
    print("=" * 70)
    print("SAFE DATABASE REINITIALIZATION")
    print("=" * 70)
    
    if not DB_PATH.exists():
        print("\n⚠️  Database does not exist. Creating new database...")
        reinitialize_database()
        print("✓ New database created with seed data (admin1, doctor1, patient1)")
        return
    
    # Check current data
    doctor_count = get_doctor_count()
    user_count = get_user_count()
    doctors = get_doctor_names()
    
    print(f"\nCurrent Database State:")
    print(f"  • Total Users: {user_count}")
    print(f"  • Doctors: {doctor_count}")
    
    if doctor_count > 0:
        print(f"\n⚠️  WARNING: The following doctors will be DELETED:")
        for username, email in doctors:
            print(f"  • {username} ({email})")
    
    print(f"\n  All user data will be reset to:")
    print(f"  • admin1 (admin)")
    print(f"  • doctor1 (doctor)")
    print(f"  • patient1 (patient)")
    
    print("\n" + "=" * 70)
    
    if doctor_count > 0 or user_count > 3:
        response = input("⚠️  Are you SURE you want to reinitialize? (type 'YES' to confirm): ").strip().upper()
        
        if response != "YES":
            print("❌ Cancelled. Database not changed.")
            return
    
    print("\n🔄 Reinitializing database...")
    if reinitialize_database():
        print("\n✅ Database reinitialized successfully!")
        print("   Seed data loaded (admin1, doctor1, patient1)")
        print("\n💡 To add doctors without losing them:")
        print("   1. Use admin dashboard to create doctors")
        print("   2. DO NOT run this script again")
        print("   3. Data will persist across app restarts")
    else:
        print("\n❌ Reinitialization failed")

if __name__ == "__main__":
    main()

