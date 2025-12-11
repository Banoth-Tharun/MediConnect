import os
import sqlite3
import random
import string
from datetime import datetime, timezone, timedelta
from pathlib import Path
from functools import wraps
from typing import Optional

from flask import Flask, g, redirect, render_template, request, session, url_for, jsonify, send_file, abort
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")
app.config["DATABASE"] = str(BASE_DIR / "app.db")

# In-memory placeholders for prescriptions and reports (demo only).
PRESCRIPTIONS_STORE = []  # each: {"id": int, "patient_id": int, "doctor": str, "medication": str, "notes": str, "date": str}
REPORTS_STORE = []  # each: {"id": int, "patient_id": int, "doctor": str, "title": str, "filename": str, "date": str, "flag": str}
REPORT_COUNTER = 1
PRESCRIPTION_COUNTER = 1

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception: Optional[BaseException]) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def log_action(user: str, role: str, action: str, endpoint: str) -> None:
    """
    Record an action in the logs table.
    """
    conn = get_db()
    ts = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO logs (timestamp, user, role, action, endpoint) VALUES (?, ?, ?, ?, ?)",
        (ts, user, role, action, endpoint),
    )
    conn.commit()


def load_user(username: str) -> Optional[sqlite3.Row]:
    conn = get_db()
    cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def generate_otp() -> str:
    """Generate a 6-digit OTP."""
    return ''.join(random.choices(string.digits, k=6))


def send_otp_email(email: str, otp: str) -> bool:
    """
    Send OTP to user's email.
    For demo purposes, we display the OTP in the terminal.
    In production, use a library like smtplib or sendgrid.
    """
    print("\n" + "="*60)
    print("📧 OTP VERIFICATION")
    print("="*60)
    print(f"Email: {email}")
    print(f"OTP Code: {otp}")
    print("="*60 + "\n")
    # Simulate email sending success
    return True


def create_otp_token(email: str) -> str:
    """Create and store OTP token in database."""
    conn = get_db()
    otp_code = generate_otp()
    created_at = datetime.now(timezone.utc).isoformat()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    
    conn.execute(
        "INSERT INTO otp_tokens (email, otp_code, created_at, expires_at, is_used) VALUES (?, ?, ?, ?, 0)",
        (email, otp_code, created_at, expires_at)
    )
    conn.commit()
    return otp_code


def verify_otp(email: str, otp_code: str) -> bool:
    """Verify OTP token."""
    conn = get_db()
    current_time = datetime.now(timezone.utc).isoformat()
    
    row = conn.execute(
        "SELECT * FROM otp_tokens WHERE email = ? AND otp_code = ? AND is_used = 0 AND expires_at > ?",
        (email, otp_code, current_time)
    ).fetchone()
    
    if row:
        # Mark OTP as used
        conn.execute("UPDATE otp_tokens SET is_used = 1 WHERE id = ?", (row['id'],))
        conn.commit()
        return True
    return False


def require_role(role: str):
    def wrapper(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = session.get("user")
            if not user or user.get("role") != role:
                return "Access Denied", 403
            log_action(user["username"], user["role"], "access", request.path)
            return view(*args, **kwargs)

        return wrapped

    return wrapper


@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect_by_role(session["user"]["role"])

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = load_user(username)

        if user and check_password_hash(user["password_hash"], password):
            if user["is_verified"] == 0:
                error = "Please verify your email before logging in."
            elif user["role"] == "doctor":
                # For doctors, generate OTP and send it
                if user["email"]:
                    otp = create_otp_token(user["email"])
                    send_otp_email(user["email"], otp)
                    session["pending_login_username"] = username
                    session["pending_login_email"] = user["email"]
                    session["pending_login_role"] = "doctor"
                    return redirect(url_for("verify_login_otp"))
                else:
                    error = "Doctor account does not have an email set."
            else:
                session["user"] = {"username": user["username"], "role": user["role"]}
                log_action(user["username"], user["role"], "login", request.path)
                return redirect_by_role(user["role"])
        else:
            error = "Invalid username or password"

    return render_template("login.html", error=error)


def redirect_by_role(role: str):
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    if role == "doctor":
        return redirect(url_for("doctor_dashboard"))
    if role == "patient":
        return redirect(url_for("patient_dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Patient registration endpoint."""
    if session.get("user"):
        return redirect_by_role(session["user"]["role"])
    
    error = None
    success = None
    
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        # Validation
        if not all([first_name, last_name, email, username, password, confirm_password]):
            error = "All fields are required."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif len(password) < 6:
            error = "Password must be at least 6 characters long."
        elif "@" not in email:
            error = "Please enter a valid email address."
        else:
            # Check if username or email already exists
            conn = get_db()
            existing_user = conn.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email)).fetchone()
            
            if existing_user:
                error = "Username or email already exists."
            else:
                # Create user account (unverified)
                hashed_password = generate_password_hash(password)
                try:
                    conn.execute(
                        "INSERT INTO users (username, password_hash, role, email, first_name, last_name, is_verified) VALUES (?, ?, ?, ?, ?, ?, 0)",
                        (username, hashed_password, "patient", email, first_name, last_name)
                    )
                    conn.commit()
                    
                    # Generate and send OTP
                    otp = create_otp_token(email)
                    if send_otp_email(email, otp):
                        session["pending_email"] = email
                        session["pending_username"] = username
                        return redirect(url_for("verify_otp_page"))
                    else:
                        error = "Failed to send OTP. Please try again."
                        # Delete the unverified user
                        conn.execute("DELETE FROM users WHERE username = ?", (username,))
                        conn.commit()
                except sqlite3.IntegrityError:
                    error = "Username or email already exists."
    
    return render_template("register.html", error=error, success=success)


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp_page():
    """OTP verification endpoint."""
    if session.get("user"):
        return redirect_by_role(session["user"]["role"])
    
    email = session.get("pending_email")
    username = session.get("pending_username")
    
    if not email or not username:
        return redirect(url_for("register"))
    
    error = None
    
    if request.method == "POST":
        otp_code = request.form.get("otp_code", "").strip()
        
        if not otp_code:
            error = "OTP is required."
        elif verify_otp(email, otp_code):
            # Mark user as verified
            conn = get_db()
            conn.execute("UPDATE users SET is_verified = 1 WHERE username = ?", (username,))
            conn.commit()
            
            # Log the registration
            log_action(username, "patient", "register", request.path)
            
            # Automatically log in the user as a patient
            session["user"] = {"username": username, "role": "patient"}
            log_action(username, "patient", "auto_login_after_verification", request.path)
            
            # Clear session data
            session.pop("pending_email", None)
            session.pop("pending_username", None)
            
            # Redirect to patient dashboard
            return redirect(url_for("patient_dashboard"))
        else:
            error = "Invalid or expired OTP. Please try again."
    
    return render_template("verify_otp.html", email=email, error=error)


@app.route("/verify-login-otp", methods=["GET", "POST"])
def verify_login_otp():
    """OTP verification during doctor login."""
    username = session.get("pending_login_username")
    email = session.get("pending_login_email")
    role = session.get("pending_login_role")
    
    if not username or not email or role != "doctor":
        return redirect(url_for("login"))
    
    error = None
    
    if request.method == "POST":
        otp_code = request.form.get("otp_code", "").strip()
        
        if not otp_code:
            error = "OTP is required."
        elif verify_otp(email, otp_code):
            # Log in the doctor
            session["user"] = {"username": username, "role": "doctor"}
            log_action(username, "doctor", "login_with_otp", request.path)
            
            # Clear session data
            session.pop("pending_login_username", None)
            session.pop("pending_login_email", None)
            session.pop("pending_login_role", None)
            
            # Redirect to doctor dashboard
            return redirect(url_for("doctor_dashboard"))
        else:
            error = "Invalid or expired OTP. Please try again."
    
    return render_template("verify_login_otp.html", email=email, error=error)


def redirect_by_role(role: str):
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    if role == "doctor":
        return redirect(url_for("doctor_dashboard"))
    if role == "patient":
        return redirect(url_for("patient_dashboard"))
    return redirect(url_for("login"))


@app.route("/admin", methods=["GET", "POST"])
@require_role("admin")
def admin_dashboard():
    success_message = None
    error_message = None

    if request.method == "POST":
        username = request.form.get("doctor_username", "").strip()
        email = request.form.get("doctor_email", "").strip()
        password = request.form.get("doctor_password", "")

        if not username or not email or not password:
            error_message = "Username, email, and password are required to add a doctor."
        elif "@" not in email:
            error_message = "Please enter a valid email address."
        else:
            try:
                hashed = generate_password_hash(password)
                conn = get_db()
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, email, is_verified) VALUES (?, ?, 'doctor', ?, 1)",
                    (username, hashed, email),
                )
                conn.commit()
                log_action(session["user"]["username"], session["user"]["role"], "create_doctor", request.path)
                success_message = f"Doctor '{username}' added successfully with email {email}."
            except sqlite3.IntegrityError:
                error_message = "Username already exists. Choose another."

    conn = get_db()
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_admins = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
    total_doctors = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'doctor'").fetchone()[0]
    total_patients = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'patient'").fetchone()[0]

    users = conn.execute(
        "SELECT id, username, role FROM users ORDER BY id DESC"
    ).fetchall()

    audit_logs = conn.execute(
        "SELECT timestamp, user, role, action, endpoint FROM logs ORDER BY id DESC LIMIT 100"
    ).fetchall()

    return render_template(
        "admin_dashboard.html",
        user=session.get("user"),
        success_message=success_message,
        error_message=error_message,
        total_users=total_users,
        total_admins=total_admins,
        total_doctors=total_doctors,
        total_patients=total_patients,
        users=users,
        audit_logs=audit_logs,
    )


@app.route("/doctor")
@require_role("doctor")
def doctor_dashboard():
    # Fetch all patients with their details from the database
    conn = get_db()
    patient_rows = conn.execute("SELECT id, username, email, first_name, last_name FROM users WHERE role = 'patient'").fetchall()
    patients = [
        {
            "id": row["id"],
            "username": row["username"],
            "name": f"{row['first_name']} {row['last_name']}" if row['first_name'] and row['last_name'] else row["username"],
            "first_name": row["first_name"] or "N/A",
            "last_name": row["last_name"] or "N/A",
            "email": row["email"] or "N/A",
            "contact": "N/A",
        }
        for row in patient_rows
    ]
    # Appointments for this doctor - removed from in-memory store
    doctor_id = _get_user_id(session["user"]["username"])
    
    # Reports for all patients (doctor view)
    reports = [
        {
            "id": rep["id"],
            "patient_name": next((p["name"] for p in patients if p["id"] == rep["patient_id"]), "Unknown"),
            "filename": rep["filename"],
            "uploaded_on": rep["date"],
        }
        for rep in REPORTS_STORE
    ]
    return render_template(
        "doctor_dashboard.html",
        user=session.get("user"),
        patients=patients,
        reports=reports,
    )


@app.route("/patient")
@require_role("patient")
def patient_dashboard():
    records = []
    user = session.get("user")
    patient_id = _get_patient_id(user["username"]) if user else -1
    # Filter prescriptions and reports for this patient
    patient_prescriptions = [
        {
            "id": p["id"],
            "medication": p["medication"],
            "doctor": p["doctor"],
            "prescribed_on": datetime.fromisoformat(p["date"]),
            "notes": p.get("notes", ""),
        }
        for p in PRESCRIPTIONS_STORE
        if patient_id != -1 and p["patient_id"] == patient_id
    ]
    patient_reports = [
        {
            "title": r["title"],
            "date": datetime.fromisoformat(r["date"]),
            "type": r["filename"],
            "flag": r.get("flag") or "normal",
            "summary": "Secure report available for download.",
            "view_url": url_for("download_report", report_id=r["id"]),
            "download_url": url_for("download_report", report_id=r["id"]),
        }
        for r in REPORTS_STORE
        if patient_id != -1 and r["patient_id"] == patient_id
    ]
    doctors = _get_doctors()
    
    # Get appointments from database
    conn = get_db()
    appointment_rows = conn.execute(
        """SELECT a.id, a.doctor_id, a.scheduled_at, a.reason, a.status, 
                  u.username, u.first_name, u.last_name
           FROM appointments a 
           JOIN users u ON a.doctor_id = u.id 
           WHERE a.patient_id = ? 
           ORDER BY a.scheduled_at DESC""",
        (patient_id,)
    ).fetchall()
    
    appointments = [
        {
            "id": ap["id"],
            "doctor_id": ap["doctor_id"],
            "doctor_name": f"{ap['first_name']} {ap['last_name']}" if ap['first_name'] and ap['last_name'] else ap["username"],
            "scheduled_at": datetime.fromisoformat(ap["scheduled_at"]),
            "reason": ap["reason"],
            "status": ap["status"],
        }
        for ap in appointment_rows
    ]
    
    return render_template(
        "patient_dashboard.html",
        user=session.get("user"),
        records=records,
        prescriptions=patient_prescriptions,
        reports=patient_reports,
        doctors=doctors,
        appointments=appointments,
    )


@app.route("/book_appointment", methods=["GET", "POST"])
@require_role("patient")
def book_appointment():
    """
    Patient books an appointment with a doctor.
    """
    user = session.get("user")
    if request.method == "GET":
        return redirect(url_for("patient_dashboard"))

    patient_id = _get_patient_id(user["username"]) if user else -1
    doctor_id = request.form.get("doctor_id")
    date = request.form.get("date")
    time_str = request.form.get("time")
    reason = request.form.get("reason", "")
    
    if not (patient_id != -1 and doctor_id and date and time_str):
        return redirect(url_for("patient_dashboard"))
    
    try:
        did = int(doctor_id)
    except ValueError:
        return redirect(url_for("patient_dashboard"))
    
    conn = get_db()
    scheduled_at = f"{date}T{time_str}"
    created_at = datetime.now(timezone.utc).isoformat()
    
    conn.execute(
        "INSERT INTO appointments (patient_id, doctor_id, scheduled_at, reason, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
        (patient_id, did, scheduled_at, reason, created_at)
    )
    conn.commit()
    
    if user:
        log_action(user["username"], user["role"], "book_appointment", request.path)
    
    return redirect(url_for("patient_dashboard"))


@app.route("/doctor_appointments")
@require_role("doctor")
def doctor_appointments():
    """
    Show all appointment requests for this doctor.
    """
    user = session.get("user")
    doctor_id = _get_user_id(user["username"])
    
    conn = get_db()
    appointments = conn.execute(
        """SELECT a.id, a.patient_id, a.scheduled_at, a.reason, a.status, a.created_at, 
                  u.username, u.first_name, u.last_name, u.email
           FROM appointments a 
           JOIN users u ON a.patient_id = u.id 
           WHERE a.doctor_id = ? 
           ORDER BY a.created_at DESC""",
        (doctor_id,)
    ).fetchall()
    
    appointment_list = [
        {
            "id": a["id"],
            "patient_id": a["patient_id"],
            "patient_username": a["username"],
            "patient_name": f"{a['first_name']} {a['last_name']}" if a['first_name'] and a['last_name'] else a["username"],
            "patient_email": a["email"],
            "scheduled_at": a["scheduled_at"],
            "reason": a["reason"],
            "status": a["status"],
            "created_at": a["created_at"],
        }
        for a in appointments
    ]
    
    log_action(user["username"], user["role"], "view_appointments", request.path)
    
    return render_template("doctor_appointments.html", user=user, appointments=appointment_list)


@app.route("/approve_appointment/<int:appointment_id>", methods=["POST"])
@require_role("doctor")
def approve_appointment(appointment_id: int):
    """
    Doctor approves an appointment.
    """
    user = session.get("user")
    doctor_id = _get_user_id(user["username"])
    
    conn = get_db()
    appointment = conn.execute(
        "SELECT doctor_id, status FROM appointments WHERE id = ?", 
        (appointment_id,)
    ).fetchone()
    
    if not appointment or appointment["doctor_id"] != doctor_id:
        return redirect(url_for("doctor_appointments"))
    
    conn.execute("UPDATE appointments SET status = 'approved' WHERE id = ?", (appointment_id,))
    conn.commit()
    
    log_action(user["username"], user["role"], "approve_appointment", request.path)
    
    return redirect(url_for("doctor_appointments"))


@app.route("/reject_appointment/<int:appointment_id>", methods=["POST"])
@require_role("doctor")
def reject_appointment(appointment_id: int):
    """
    Doctor rejects an appointment.
    """
    user = session.get("user")
    doctor_id = _get_user_id(user["username"])
    
    conn = get_db()
    appointment = conn.execute(
        "SELECT doctor_id, status FROM appointments WHERE id = ?", 
        (appointment_id,)
    ).fetchone()
    
    if not appointment or appointment["doctor_id"] != doctor_id:
        return redirect(url_for("doctor_appointments"))
    
    conn.execute("UPDATE appointments SET status = 'rejected' WHERE id = ?", (appointment_id,))
    conn.commit()
    
    log_action(user["username"], user["role"], "reject_appointment", request.path)
    
    return redirect(url_for("doctor_appointments"))


@app.route("/prescription/<int:prescription_id>/download")
@require_role("patient")
def download_prescription(prescription_id: int):
    """
    Placeholder download endpoint referenced by the patient dashboard.
    """
    user = session.get("user")
    if user:
        log_action(user["username"], user["role"], "download_prescription", request.path)
    # For now just return a simple text response.
    return f"Download for prescription {prescription_id} is not implemented yet.", 200


@app.route("/cancel_appointment/<int:appointment_id>")
@require_role("patient")
def cancel_appointment(appointment_id: int):
    user = session.get("user")
    if user:
        log_action(user["username"], user["role"], "cancel_appointment", request.path)
    return f"Appointment {appointment_id} cancellation not implemented.", 200


@app.route("/write_prescription", methods=["POST"])
@require_role("doctor")
def write_prescription():
    """
    Placeholder endpoint for saving a prescription from the doctor dashboard.
    """
    user = session.get("user")
    if user:
        log_action(user["username"], user["role"], "write_prescription", request.path)
    patient_id = request.form.get("patient_id")
    text = request.form.get("prescription_text", "").strip()
    med = text.splitlines()[0] if text else "Medication"
    global PRESCRIPTION_COUNTER
    try:
        pid = int(patient_id)
        PRESCRIPTIONS_STORE.append(
            {
                "id": PRESCRIPTION_COUNTER,
                "patient_id": pid,
                "doctor": user["username"] if user else "doctor",
                "medication": med,
                "notes": text,
                "date": datetime.now(timezone.utc).isoformat(),
            }
        )
        PRESCRIPTION_COUNTER += 1
    except (TypeError, ValueError):
        pass
    return redirect(url_for("doctor_dashboard"))


@app.route("/upload_report", methods=["POST"])
@require_role("doctor")
def upload_report():
    """
    Placeholder endpoint for uploading a report.
    """
    user = session.get("user")
    if user:
        log_action(user["username"], user["role"], "upload_report", request.path)
    patient_id = request.form.get("patient_id")
    file = request.files.get("report_file")
    global REPORT_COUNTER
    try:
        pid = int(patient_id)
        filename = file.filename if file else "report.pdf"
        REPORTS_STORE.append(
            {
                "id": REPORT_COUNTER,
                "patient_id": pid,
                "doctor": user["username"] if user else "doctor",
                "title": filename,
                "filename": filename,
                "date": datetime.now(timezone.utc).isoformat(),
                "flag": "normal",
            }
        )
        REPORT_COUNTER += 1
    except (TypeError, ValueError):
        pass
    return redirect(url_for("doctor_dashboard"))


@app.route("/report/<int:report_id>")
@require_role("doctor")
def view_report(report_id: int):
    """
    Placeholder endpoint to view a report.
    """
    user = session.get("user")
    if user:
        log_action(user["username"], user["role"], "view_report", request.path)
    return f"Report {report_id} viewer is not implemented yet.", 200


@app.route("/report/<int:report_id>/download")
@require_role("patient")
def download_report(report_id: int):
    """
    Placeholder secure download for patient reports.
    """
    user = session.get("user")
    rep = next((r for r in REPORTS_STORE if r["id"] == report_id), None)
    if not rep or not user or rep["patient_id"] != _get_patient_id(user["username"]):
        abort(404)
    log_action(user["username"], user["role"], "download_report", request.path)
    # Return a simple text payload to simulate download
    return f"Report {report_id} ({rep['filename']}) download is not implemented.", 200


def _get_patient_id(username: str) -> int:
    conn = get_db()
    row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    return row["id"] if row else -1


def _get_user_id(username: str) -> int:
    conn = get_db()
    row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    return row["id"] if row else -1


def _get_doctors():
    conn = get_db()
    rows = conn.execute("SELECT id, username FROM users WHERE role = 'doctor'").fetchall()
    return [
        {
            "id": r["id"],
            "username": r["username"],
            "display_name": r["username"],
            "specialty": "General",
            "experience": 5,
        }
        for r in rows
    ]


def _get_doctor_name(doctor_id: int) -> str:
    conn = get_db()
    row = conn.execute("SELECT username FROM users WHERE id = ?", (doctor_id,)).fetchone()
    return row["username"] if row else "Doctor"


@app.route("/logout")
def logout():
    user = session.pop("user", None)
    if user:
        log_action(user["username"], user["role"], "logout", request.path)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)

