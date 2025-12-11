import sqlite3

conn = sqlite3.connect('app.db')
cur = conn.cursor()

print("\n" + "="*70)
print("DOCTOR STATUS CHECK")
print("="*70)

# Get all doctors
doctors = cur.execute('SELECT id, username, email, is_verified FROM users WHERE role = "doctor"').fetchall()
print(f"\nDoctors in database: {len(doctors)}")
for doc in doctors:
    print(f"  ID: {doc[0]} | Username: {doc[1]} | Email: {doc[2]} | Verified: {doc[3]}")

# Get all users
all_users = cur.execute('SELECT id, username, role FROM users').fetchall()
print(f"\nTotal Users: {len(all_users)}")
for user in all_users:
    print(f"  ID: {user[0]} | Username: {user[1]} | Role: {user[2]}")

# Check logs for doctor creation/deletion
logs = cur.execute('SELECT timestamp, user, action FROM logs WHERE action LIKE "%doctor%" ORDER BY timestamp DESC LIMIT 10').fetchall()
print(f"\nRecent doctor-related actions:")
for log in logs:
    print(f"  {log[0]} | {log[1]} | {log[2]}")

print("\n" + "="*70 + "\n")
conn.close()
