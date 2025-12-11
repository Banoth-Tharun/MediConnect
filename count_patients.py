import sqlite3

conn = sqlite3.connect('app.db')
cur = conn.cursor()

# Count patients
patient_count = cur.execute('SELECT COUNT(*) FROM users WHERE role = "patient"').fetchone()[0]
# Count all users
total_count = cur.execute('SELECT COUNT(*) FROM users').fetchone()[0]
# Get patient details
patients = cur.execute('SELECT id, username, email, first_name, last_name FROM users WHERE role = "patient"').fetchall()

print(f"\n{'='*60}")
print(f"PATIENT STATISTICS")
print(f"{'='*60}")
print(f"Total Patients in Database: {patient_count}")
print(f"Total Users in Database: {total_count}")
print(f"\n{'PATIENT DETAILS':^60}")
print(f"{'='*60}")

if patients:
    for patient in patients:
        id, username, email, first_name, last_name = patient
        name = f"{first_name} {last_name}" if first_name and last_name else "N/A"
        print(f"ID: {id} | Name: {name} | Username: {username} | Email: {email}")
else:
    print("No patients found in database.")

print(f"{'='*60}\n")
conn.close()
