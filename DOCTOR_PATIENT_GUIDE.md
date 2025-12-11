# MEDICAL CARE SYSTEM - DOCTOR & PATIENT ACCESS GUIDE

## Current System Status

### Users in Database:
- **Doctors:** 1 (doctor1)
- **Patients:** 1 (patient1)
- **Admins:** 1 (admin1)

---

## HOW DOCTORS ACCESS PATIENT DATA

### ✅ FEATURE 1: View All Patients
When a doctor logs in and goes to the Doctor Dashboard:
1. Clicks on "View My Patients" button
2. Sees a table with ALL patients in the database showing:
   - First Name
   - Last Name
   - Username
   - Email Address
   - Actions (View Details button)

**Backend Logic:** In `app.py`, the `doctor_dashboard()` function queries:
```python
SELECT id, username, email, first_name, last_name FROM users WHERE role = 'patient'
```
This ensures EVERY doctor sees ALL patients in the system.

---

### ✅ FEATURE 2: Write Prescriptions
Steps for a doctor to write a prescription:
1. Log in with credentials (username: doctor1, password: password@123)
2. Enter OTP when prompted (OTP shown in terminal)
3. On Doctor Dashboard, click "Write Prescription"
4. Select a patient from dropdown (shows all patients with First Name, Last Name, Username)
5. Enter prescription details in text area
6. Click "Save Prescription"

**What happens:**
- Prescription is stored in PRESCRIPTIONS_STORE (in-memory)
- Patient can view it on their dashboard under "Prescriptions"
- Prescription includes: medication, doctor name, date, and notes

---

### ✅ FEATURE 3: Upload Reports
Steps for a doctor to upload a report:
1. Log in to Doctor Dashboard
2. Click "Upload / View Reports" tab
3. Select a patient from dropdown (all patients available)
4. Select a report file (.pdf, .jpg, .png)
5. Click "Upload Report"

**What happens:**
- Report is stored in REPORTS_STORE (in-memory)
- Report information includes: patient ID, doctor name, filename, upload date
- Patient can view and download the report on their dashboard

---

### ✅ FEATURE 4: View Upcoming Appointments
Doctors can see appointments with their patients:
1. Click "View Appointments" tab
2. See all appointments scheduled with this doctor showing:
   - Patient name
   - Date & Time
   - Appointment reason

---

## DATABASE SCHEMA

### Users Table:
```sql
- id: INTEGER (Primary Key)
- username: TEXT (Unique)
- password_hash: TEXT
- role: TEXT ('admin', 'doctor', 'patient')
- email: TEXT
- first_name: TEXT
- last_name: TEXT
- is_verified: INTEGER (0 or 1)
```

### OTP Tokens Table:
```sql
- id: INTEGER (Primary Key)
- email: TEXT
- otp_code: TEXT (6 digits)
- created_at: TEXT
- expires_at: TEXT (10 minutes)
- is_used: INTEGER (0 or 1)
```

---

## HOW TO ADD MORE PATIENTS

### Method 1: Through Registration (With OTP)
1. Go to login page
2. Click "Create Account as Patient" button
3. Fill in: First Name, Last Name, Email, Username, Password
4. Submit registration
5. OTP will be displayed in terminal
6. Enter OTP on verification page
7. Patient account is created and verified

### Method 2: Through Admin Dashboard
1. Admin can create doctors with email addresses
2. To create patients, use the registration page (Method 1)

---

## HOW TO ADD MORE DOCTORS

### Through Admin Dashboard:
1. Log in as admin (username: Tharun Admin, password: password@123)
2. In Admin Dashboard, go to "Add Doctor" section
3. Enter:
   - Doctor username
   - Temporary password
   - Doctor email address (REQUIRED for OTP login)
4. Click "Create Doctor"
5. New doctor will appear in the system

---

## DOCTOR LOGIN FLOW WITH OTP

1. Doctor enters username & password
2. If credentials are correct:
   - System generates a 6-digit OTP
   - OTP is displayed in terminal
   - Doctor is sent to OTP verification page
3. Doctor enters the OTP code
4. System validates OTP (must be within 10 minutes)
5. Doctor is authenticated and sent to Doctor Dashboard

---

## DATA STORED (In-Memory)

### Prescriptions:
- id, patient_id, doctor_name, medication, notes, date

### Reports:
- id, patient_id, doctor_name, title, filename, date, flag

### Appointments:
- id, patient_id, doctor_id, doctor_name, scheduled_at, status, reason

**Note:** In-memory storage means data is lost when app restarts. For production, migrate to database.

---

## KEY FEATURES IMPLEMENTED

✅ Patient Registration with OTP Email Verification
✅ Doctor Login with OTP Security
✅ Admin Panel to Create Doctors
✅ Doctors can view ALL patients in database
✅ Doctors can write prescriptions for ANY patient
✅ Doctors can upload reports for ANY patient
✅ Patients can view their prescriptions
✅ Patients can view and download their reports
✅ Patients can book appointments
✅ Audit logging of all actions
✅ Role-based access control (Admin, Doctor, Patient)

---

## TEST CREDENTIALS

### Admin:
- Username: Tharun Admin
- Password: password@123

### Doctor:
- Username: doctor1
- Password: password@123
- Email: doctor1@hospital.com

### Patient:
- Username: patient1
- Password: password@123
- Email: patient1@example.com

---

## NEXT STEPS

1. ✅ Create new patient accounts via registration
2. ✅ Create new doctors via admin dashboard
3. ✅ Doctor logs in with OTP verification
4. ✅ Doctor selects any patient and writes prescription
5. ✅ Doctor uploads report for patient
6. ✅ Patient views their data on their dashboard

