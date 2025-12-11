#!/usr/bin/env python3
"""
Verify Doctor Persistence
Checks if doctors are actually being deleted or if it's just reinitialization.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "app.db"

def check_doctor_persistence():
    """Check current doctors in database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, email, role, is_verified FROM users WHERE role = 'doctor'")
        doctors = cursor.fetchall()
        
        print("=" * 60)
        print("DOCTORS IN DATABASE (Current State)")
        print("=" * 60)
        
        if not doctors:
            print("❌ No doctors found in database")
            return False
        
        print(f"✓ Found {len(doctors)} doctor(s):\n")
        for doctor in doctors:
            print(f"  ID: {doctor['id']}")
            print(f"  Username: {doctor['username']}")
            print(f"  Email: {doctor['email']}")
            print(f"  Role: {doctor['role']}")
            print(f"  Verified: {'Yes ✓' if doctor['is_verified'] else 'No ✗'}")
            print()
        
        # Check if doctors have appointments
        cursor.execute("""
            SELECT COUNT(*) as count FROM appointments 
            WHERE doctor_id IN (SELECT id FROM users WHERE role = 'doctor')
        """)
        appt_count = cursor.fetchone()['count']
        print(f"📋 Appointments assigned to doctors: {appt_count}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def check_all_users():
    """Show all users in database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, role, email FROM users ORDER BY role DESC")
        users = cursor.fetchall()
        
        print("\n" + "=" * 60)
        print("ALL USERS IN DATABASE")
        print("=" * 60)
        
        roles = {}
        for user in users:
            role = user['role']
            if role not in roles:
                roles[role] = []
            roles[role].append(user)
        
        for role in ['admin', 'doctor', 'patient']:
            if role in roles:
                print(f"\n{role.upper()} ({len(roles[role])}):")
                for user in roles[role]:
                    print(f"  - {user['username']} ({user['email']})")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    print("🔍 Checking doctor persistence...\n")
    
    has_doctors = check_doctor_persistence()
    check_all_users()
    
    print("\n" + "=" * 60)
    if has_doctors:
        print("✅ Doctors exist in database and are persistent")
        print("\n⚠️  IMPORTANT: Doctors are ONLY deleted if you run:")
        print("   python init_db.py")
        print("\n💡 TIP: Use admin dashboard to add/manage doctors")
        print("        DO NOT run init_db.py after initial setup")
    else:
        print("⚠️  No doctors found. Check if:")
        print("   1. You haven't created any doctors yet")
        print("   2. Database was just reinitialized")
        print("   3. You need to run: python init_db.py")
    print("=" * 60)

