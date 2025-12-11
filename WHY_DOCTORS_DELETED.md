# ⚠️ WHY DOCTORS ARE GETTING DELETED

## ROOT CAUSE

When you run `python init_db.py`, it:
1. Drops ALL tables (including users, appointments, logs)
2. Recreates them from scratch
3. Only loads the seed data (admin1, doctor1, patient1)
4. **Any doctors added through the admin dashboard are deleted**

---

## HOW DOCTOR DELETION HAPPENS

### Scenario 1: Running init_db.py After Adding Doctors
```
1. Admin creates doctor2 via dashboard
   → Stored in database ✓
2. Developer runs: python init_db.py
   → DROP TABLE users ✗
   → doctor2 DELETED ✗
   → Only seed data remains
```

### Scenario 2: No Cascade Delete Issue
- Our database doesn't have CASCADE DELETE
- But `DROP TABLE` deletes everything regardless
- Doctors aren't "cascading deleted" - they're just lost when table is reset

---

## HOW TO AVOID THIS

### ✅ Option 1: Never Run init_db.py After First Setup
```bash
# Only run ONCE at the beginning
python init_db.py

# Then only add doctors through admin dashboard
# They will persist
```

### ✅ Option 2: Use Backup and Restore
```bash
# After adding doctors, backup is created automatically
# If you accidentally run init_db.py:
python init_db.py  # Creates backup_YYYYMMDD_HHMMSS.db

# Restore from backup if needed
```

### ✅ Option 3: Never Reinitialize
- Don't run `init_db.py` after first initialization
- Use admin dashboard to manage users
- Use admin dashboard to manage doctors

---

## DATABASE INITIALIZATION FLOW

### First Time Setup:
```
python init_db.py
  ↓
Creates fresh database with:
  - admin1 (admin)
  - doctor1 (doctor)
  - patient1 (patient)
```

### After First Setup:
```
Use Admin Dashboard to:
  - Create new doctors
  - Create new users
  
DO NOT run init_db.py again
```

---

## WHAT ACTUALLY HAPPENS

### When Doctors Are Added Via Admin Dashboard:
```sql
INSERT INTO users (username, password_hash, role, email, is_verified) 
VALUES ('doctor2', 'hashed_password', 'doctor', 'doctor2@hospital.com', 1)
```
✓ Stored in database
✓ Persists across app restarts
✓ **ONLY deleted if database is reinitialized**

### When init_db.py Runs:
```sql
DROP TABLE IF EXISTS users;  -- DELETE ALL DOCTORS!
CREATE TABLE users ...;
INSERT INTO users VALUES ('admin1', ...);  -- Only seed data
INSERT INTO users VALUES ('doctor1', ...);
INSERT INTO users VALUES ('patient1', ...);
```
✗ All previously added doctors are gone
✗ All appointments are gone
✗ All patient registrations are gone

---

## TESTING WITHOUT LOSING DATA

### Safe Testing:
1. Create doctors via admin dashboard
2. Create patients via registration
3. Book appointments
4. Approve/reject appointments
5. Write prescriptions
6. Upload reports

**All data persists** ✓

### Dangerous Operations:
- Running `python init_db.py` again
- Deleting `app.db` file
- Stopping the app and restarting (data persists, safe)

---

## RECOMMENDED WORKFLOW

### Development:
```
1. python init_db.py          # ONE TIME ONLY at start
2. Run app: python app.py     # Start the app
3. Use admin dashboard        # Add doctors, manage users
4. Test features              # Book appointments, etc.
5. Data persists ✓           # Across app restarts
```

### If Database Gets Corrupted:
```
1. Check backup: app_backup_YYYYMMDD_HHMMSS.db
2. Delete corrupted app.db
3. Restore from backup or run init_db.py fresh
4. Start over (losing all custom data)
```

---

## CURRENT STATUS

✓ Doctors created via admin dashboard are NOT automatically deleted
✓ Doctors persist in database after creation
✓ Doctors only "disappear" if database is reinitialized

**Doctors are only deleted when you run `python init_db.py` again**

