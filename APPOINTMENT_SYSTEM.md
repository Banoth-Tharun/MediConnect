# APPOINTMENT BOOKING & APPROVAL SYSTEM

## ✅ COMPLETE APPOINTMENT WORKFLOW

### 1. PATIENT BOOKS APPOINTMENT
- Patient logs into their dashboard
- Clicks "Book Appointments" tab
- Selects a doctor from the list
- Enters date, time, and reason
- Clicks "Book" button
- Status: **PENDING**

### 2. DOCTOR VIEWS APPOINTMENT REQUESTS
- Doctor logs in with OTP verification
- On Dashboard, clicks **"📋 Appointment Requests"** button
- Taken to new appointment management page
- Sees ALL appointment requests (Pending, Approved, Rejected)

### 3. DOCTOR APPROVES OR REJECTS
For each pending appointment request, doctor can:
- **✓ Approve Appointment** - Changes status to "APPROVED"
- **✗ Reject Appointment** - Changes status to "REJECTED"

### 4. PATIENT SEES STATUS
- Patient dashboard shows "Upcoming Appointments" section
- Lists all appointments with their status
- Shows doctor name, date/time, and current status
- Can see reason provided

---

## DATABASE CHANGES

### New Table: `appointments`
```sql
CREATE TABLE appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    doctor_id INTEGER NOT NULL,
    scheduled_at TEXT NOT NULL,
    reason TEXT,
    status TEXT DEFAULT 'pending',  -- pending, approved, rejected
    created_at TEXT NOT NULL,
    FOREIGN KEY (patient_id) REFERENCES users(id),
    FOREIGN KEY (doctor_id) REFERENCES users(id)
);
```

### Statuses:
- **pending** - Awaiting doctor approval
- **approved** - Doctor approved the appointment
- **rejected** - Doctor rejected the appointment

---

## NEW ROUTES

### Patient Routes:
- `POST /book_appointment` - Patient books appointment

### Doctor Routes:
- `GET /doctor_appointments` - View all appointment requests
- `POST /approve_appointment/<id>` - Doctor approves appointment
- `POST /reject_appointment/<id>` - Doctor rejects appointment

---

## NEW PAGES

### `doctor_appointments.html`
Features:
- Shows all appointment requests for this doctor
- Color-coded by status (warning=pending, success=approved, error=rejected)
- Displays patient information (name, email, username)
- Shows appointment date/time and reason
- Action buttons for pending appointments
- Summary counts (Pending, Approved, Rejected)

### Updated `doctor_dashboard.html`
- Removed "View Appointments" toggle button
- Added "📋 Appointment Requests" button that links to new page
- Keeps patient, prescription, and reports sections

---

## FEATURES IMPLEMENTED

✅ Patient can book appointments with date/time/reason
✅ Appointments stored in database (persistent)
✅ Doctor sees all appointment requests in one place
✅ Doctor can approve appointments
✅ Doctor can reject appointments
✅ Patient sees appointment status on their dashboard
✅ Color-coded status indicators
✅ Doctor can see patient details for each request
✅ Appointment timestamps recorded
✅ Proper foreign key relationships

---

## HOW TO TEST

### Step 1: Patient Books Appointment
1. Log in as **patient1** (password: password@123)
2. Go to "Book Appointments" tab
3. Select doctor1 from list
4. Enter future date and time
5. Enter reason: "Check-up"
6. Click "Book"

### Step 2: Doctor Views Requests
1. Log in as **doctor1** (password: password@123)
2. Enter OTP when shown in terminal
3. On Dashboard, click **"📋 Appointment Requests"**
4. See the appointment booking from patient1

### Step 3: Doctor Approves/Rejects
1. Click **"✓ Approve Appointment"** or **"✗ Reject Appointment"**
2. Status updates immediately
3. Patient's dashboard reflects the change

### Step 4: Patient Sees Status
1. Log back in as patient1
2. Go to "Book Appointments" tab
3. Under "Upcoming Appointments" see the status

---

## DATA FLOW

```
Patient → Books Appointment
  ↓
Appointment created with status="pending"
  ↓
Doctor → Views Appointment Requests page
  ↓
Doctor → Approves/Rejects
  ↓
Appointment status updated
  ↓
Patient → Dashboard shows updated status
```

---

## BACKEND FIXES

✅ Fixed `/book_appointment` route:
  - Now stores appointments in database instead of in-memory
  - Properly validates all fields
  - Handles date/time correctly
  
✅ Removed APPOINTMENTS_STORE from memory:
  - All appointments now persistent in database
  - Survives app restarts

✅ Added appointment retrieval from database:
  - Patient dashboard pulls from database
  - Doctor appointments page queries database

---

## NOTES

- Appointments are now persistent (stored in database)
- Previous in-memory appointments will be lost when database is reinitialized
- Each appointment has full patient and doctor information stored
- Timestamps recorded for audit trail
- Foreign keys ensure data integrity

