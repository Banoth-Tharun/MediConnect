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
from werkzeug.utils import secure_filename

from security import RiskScorer, FingerprintManager, SecurityLogger, create_jwt_token

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")
app.config["DATABASE"] = str(BASE_DIR / "app.db")
app.config["ADMIN_KEY"] = os.environ.get("ADMIN_KEY", "admin123")  # Admin dashboard key
app.config["DOCTOR_VERIFY_KEY"] = os.environ.get("DOCTOR_VERIFY_KEY", "doctor@2024")  # Doctor creation verification key
app.config["DOCTOR_ACCESS_KEY"] = os.environ.get("DOCTOR_ACCESS_KEY", "secure@doc")  # Doctor access verification key
app.config["PATIENT_DETAILS_KEY"] = os.environ.get("PATIENT_DETAILS_KEY", "details@verify")  # Patient details access key
app.config["DELETE_USER_KEY"] = os.environ.get("DELETE_USER_KEY", "delete@user")  # User deletion confirmation key
app.config["REPORT_UPLOAD_KEY"] = os.environ.get("REPORT_UPLOAD_KEY", "report@upload")  # Per-upload report access key
app.config["REPORTS_FOLDER"] = str(BASE_DIR / "uploaded_reports")
app.config["REPORT_DOWNLOAD_KEY"] = os.environ.get("REPORT_DOWNLOAD_KEY", "patient@download")  # Patient-side download key

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
        
        # Get fingerprint and device info from form
        fingerprint = request.form.get("fingerprint", "unknown")
        device_os = request.form.get("device_os", "Unknown")
        device_browser = request.form.get("device_browser", "Unknown")
        
        # Get IP address
        ip_address = request.remote_addr or "unknown"
        
        user = load_user(username)
        
        # Initialize security components
        db = get_db()
        risk_scorer = RiskScorer(db)
        fingerprint_mgr = FingerprintManager(db)
        security_logger = SecurityLogger(db)
        
        # Calculate risk score
        user_id = user['id'] if user else None
        risk_assessment = risk_scorer.calculate_risk(
            user_id, username, fingerprint, ip_address,
            device_browser, device_os
        )
        
        if user and check_password_hash(user["password_hash"], password):
            # Log successful login attempt with risk score
            security_logger.log_login_attempt(
                username, user_id, fingerprint, ip_address,
                device_browser, device_os, success=True,
                risk_score=risk_assessment['risk_score'],
                risk_factors=risk_assessment['factors']
            )
            
            # Update user's last login info
            db.execute("""
                UPDATE users 
                SET last_login_ip = ?, last_login_time = ?, last_known_fingerprint = ?
                WHERE id = ?
            """, (ip_address, datetime.now(timezone.utc).isoformat(), fingerprint, user_id))
            db.commit()
            
            # Register or update fingerprint
            fingerprint_mgr.register_fingerprint(
                user_id, fingerprint,
                f"{device_browser} on {device_os}",
                device_browser, device_os, ip_address
            )
            
            if user["is_verified"] == 0:
                error = "Please verify your email before logging in."
                # Log failed verification
                security_logger.log_security_event(
                    username, user_id, "login_unverified", "medium",
                    ip_address, fingerprint, {"reason": "email_not_verified"}
                )
            elif user["role"] == "doctor":
                # For doctors, check risk level and generate OTP
                if risk_assessment['risk_level'] in ['medium', 'high']:
                    # High risk: require OTP challenge
                    session["pending_login_username"] = username
                    session["pending_login_email"] = user["email"]
                    session["pending_login_role"] = "doctor"
                    session["pending_login_risk_score"] = risk_assessment['risk_score']
                    session["pending_login_fingerprint"] = fingerprint
                    session["pending_login_ip"] = ip_address
                    session["risk_challenge_reason"] = risk_assessment['recommendation']
                    
                    # Log security event
                    security_logger.log_security_event(
                        username, user_id, "login_high_risk", risk_assessment['risk_level'],
                        ip_address, fingerprint,
                        {"risk_score": risk_assessment['risk_score'],
                         "factors": risk_assessment['factors']}
                    )
                    
                    if user["email"]:
                        otp = create_otp_token(user["email"])
                        send_otp_email(user["email"], otp)
                        
                        # Log challenge issued
                        security_logger.log_login_attempt(
                            username, user_id, fingerprint, ip_address,
                            device_browser, device_os, success=None,
                            risk_score=risk_assessment['risk_score'],
                            risk_factors=risk_assessment['factors'],
                            challenge_type="otp_doctor"
                        )
                        
                        return redirect(url_for("verify_login_otp"))
                    else:
                        error = "Doctor account does not have an email set."
                else:
                    # Low risk: Generate OTP normally
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
                # Patient or Admin
                if risk_assessment['risk_level'] == 'high':
                    # Block high-risk logins for patient/admin
                    error = "Login blocked due to suspicious activity. Please contact support."
                    
                    security_logger.log_security_event(
                        username, user_id, "login_blocked", "high",
                        ip_address, fingerprint,
                        {"reason": "high_risk_score",
                         "risk_score": risk_assessment['risk_score']}
                    )
                elif risk_assessment['risk_level'] == 'medium':
                    # Challenge with OTP for medium risk
                    session["pending_login_username"] = username
                    session["pending_login_email"] = user["email"]
                    session["pending_login_role"] = user["role"]
                    session["pending_login_fingerprint"] = fingerprint
                    session["pending_login_ip"] = ip_address
                    
                    security_logger.log_security_event(
                        username, user_id, "login_medium_risk", "medium",
                        ip_address, fingerprint,
                        {"risk_score": risk_assessment['risk_score']}
                    )
                    
                    if user["email"]:
                        otp = create_otp_token(user["email"])
                        send_otp_email(user["email"], otp)
                        return redirect(url_for("verify_login_otp"))
                else:
                    # Low risk: allow login
                    session["user"] = {"username": user["username"], "role": user["role"]}
                    log_action(user["username"], user["role"], "login", request.path)
                    
                    security_logger.log_security_event(
                        username, user_id, "login_success", "low",
                        ip_address, fingerprint,
                        {"risk_score": risk_assessment['risk_score']}
                    )
                    
                    return redirect_by_role(user["role"])
        else:
            # Failed login - log attempt
            security_logger.log_login_attempt(
                username, user_id, fingerprint, ip_address,
                device_browser, device_os, success=False,
                risk_score=risk_assessment['risk_score'],
                risk_factors=risk_assessment['factors']
            )
            
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
    """OTP verification during doctor login and high-risk challenges."""
    username = session.get("pending_login_username")
    email = session.get("pending_login_email")
    role = session.get("pending_login_role")
    risk_score = session.get("pending_login_risk_score")
    fingerprint = session.get("pending_login_fingerprint")
    ip_address = session.get("pending_login_ip")
    
    if not username or not email:
        return redirect(url_for("login"))
    
    error = None
    challenge_reason = "Doctor OTP Verification"
    
    # Check if this is a risk-based challenge
    if risk_score is not None:
        challenge_reason = f"Security Challenge (Risk Level: {session.get('risk_challenge_reason', 'medium')})"
    
    if request.method == "POST":
        otp_code = request.form.get("otp_code", "").strip()
        trust_device = request.form.get("trust_device") == "on"
        
        if not otp_code:
            error = "OTP is required."
        elif verify_otp(email, otp_code):
            # Log successful OTP verification
            db = get_db()
            security_logger = SecurityLogger(db)
            user = load_user(username)
            user_id = user['id'] if user else None
            
            security_logger.log_security_event(
                username, user_id, "otp_challenge_passed", "low",
                ip_address, fingerprint,
                {"challenge_reason": challenge_reason, "trust_device": trust_device}
            )
            
            # If device should be trusted, mark it
            if trust_device and user_id and fingerprint:
                fingerprint_mgr = FingerprintManager(db)
                fingerprint_mgr.trust_device(user_id, fingerprint, duration_days=30)
                
                security_logger.log_security_event(
                    username, user_id, "device_trusted", "low",
                    ip_address, fingerprint,
                    {"duration_days": 30}
                )
            
            # Create session for user
            session["user"] = {"username": username, "role": role}
            log_action(username, role, "login_with_otp_challenge", request.path)
            
            # Clear session data
            session.pop("pending_login_username", None)
            session.pop("pending_login_email", None)
            session.pop("pending_login_role", None)
            session.pop("pending_login_risk_score", None)
            session.pop("pending_login_fingerprint", None)
            session.pop("pending_login_ip", None)
            session.pop("risk_challenge_reason", None)
            
            # Redirect to appropriate dashboard
            return redirect_by_role(role)
        else:
            error = "Invalid or expired OTP. Please try again."
            
            # Log failed OTP verification
            if risk_score is not None:
                db = get_db()
                security_logger = SecurityLogger(db)
                user = load_user(username)
                user_id = user['id'] if user else None
                
                security_logger.log_security_event(
                    username, user_id, "otp_challenge_failed", "medium",
                    ip_address, fingerprint,
                    {"attempt": "wrong_otp"}
                )
    
    return render_template("verify_login_otp.html", 
                         email=email, 
                         error=error,
                         challenge_reason=challenge_reason,
                         risk_score=risk_score)


def redirect_by_role(role: str):
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    if role == "doctor":
        return redirect(url_for("doctor_dashboard"))
    if role == "patient":
        return redirect(url_for("patient_dashboard"))
    return redirect(url_for("login"))


@app.route("/admin-key", methods=["GET", "POST"])
@require_role("admin")
def admin_key_entry():
    """
    Admin must enter the correct admin key to access the dashboard.
    """
    error_message = None
    
    if request.method == "POST":
        entered_key = request.form.get("admin_key", "").strip()
        
        if entered_key == app.config["ADMIN_KEY"]:
            session["admin_key_verified"] = True
            return redirect(url_for("admin_dashboard"))
        else:
            error_message = "Incorrect admin key. Access denied."
    
    return render_template(
        "admin_key_entry.html",
        user=session.get("user"),
        error_message=error_message
    )


@app.route("/admin", methods=["GET", "POST"])
@require_role("admin")
def admin_dashboard():
    # Check if admin has verified the key
    if not session.get("admin_key_verified"):
        return redirect(url_for("admin_key_entry"))
    
    success_message = None
    error_message = None

    if request.method == "POST":
        username = request.form.get("doctor_username", "").strip()
        email = request.form.get("doctor_email", "").strip()
        password = request.form.get("doctor_password", "")
        doctor_verify_key = request.form.get("doctor_verify_key", "").strip()

        if not username or not email or not password:
            error_message = "Username, email, and password are required to add a doctor."
        elif "@" not in email:
            error_message = "Please enter a valid email address."
        elif not doctor_verify_key:
            error_message = "Doctor verification key is required."
        elif doctor_verify_key != app.config["DOCTOR_VERIFY_KEY"]:
            error_message = "❌ Incorrect doctor verification key. Doctor not created."
            log_action(session["user"]["username"], session["user"]["role"], "failed_doctor_creation_key", request.path)
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
                success_message = f"✅ Doctor '{username}' created successfully with email {email}."
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


@app.route("/security-audit", methods=["GET"])
@require_role("admin")
def security_audit():
    """
    Security audit dashboard showing login attempts and risk analysis
    """
    if not session.get("admin_key_verified"):
        return redirect(url_for("admin_key_entry"))
    
    db = get_db()
    security_logger = SecurityLogger(db)
    
    # Get security logs
    all_security_logs = security_logger.get_security_logs(limit=200)
    
    # Get login attempts with risk analysis
    cursor = db.cursor()
    cursor.execute("""
        SELECT * FROM login_attempts 
        ORDER BY timestamp DESC LIMIT 200
    """)
    login_attempts = [dict(row) for row in cursor.fetchall()]
    
    # Calculate statistics
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
            SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed,
            AVG(risk_score) as avg_risk,
            MAX(risk_score) as max_risk
        FROM login_attempts 
        WHERE timestamp > datetime('now', '-24 hours')
    """)
    stats_24h = dict(cursor.fetchone())
    
    # High risk events in 24h
    cursor.execute("""
        SELECT COUNT(*) as count FROM login_attempts 
        WHERE risk_score > 60 AND timestamp > datetime('now', '-24 hours')
    """)
    high_risk_24h = cursor.fetchone()['count']
    
    # Get device fingerprints
    cursor.execute("""
        SELECT COUNT(DISTINCT fingerprint) as total_devices,
               COUNT(CASE WHEN is_trusted = 1 THEN 1 END) as trusted
        FROM device_fingerprints
    """)
    device_stats = dict(cursor.fetchone())
    
    return render_template(
        "security_audit.html",
        user=session.get("user"),
        security_logs=all_security_logs,
        login_attempts=login_attempts,
        stats_24h=stats_24h,
        high_risk_24h=high_risk_24h,
        device_stats=device_stats
    )


@app.route("/delete-user/<int:user_id>", methods=["GET", "POST"])
@require_role("admin")
def delete_user_key_entry(user_id):
    """
    Admin must enter delete confirmation key to delete a user
    """
    if not session.get("admin_key_verified"):
        return redirect(url_for("admin_key_entry"))
    
    # Get user info
    conn = get_db()
    user_row = conn.execute("SELECT id, username, role, email FROM users WHERE id = ?", (user_id,)).fetchone()
    
    if not user_row:
        return "User not found", 404
    
    error_message = None
    
    if request.method == "POST":
        entered_key = request.form.get("delete_user_key", "").strip()
        
        if entered_key == app.config["DELETE_USER_KEY"]:
            # Delete the user
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            log_action(session["user"]["username"], "admin", f"deleted_user_{user_row['username']}", request.path)
            return redirect(url_for("admin_dashboard"))
        else:
            error_message = "❌ Incorrect deletion confirmation key. User not deleted."
            log_action(session["user"]["username"], "admin", f"failed_delete_user_{user_id}", request.path)
    
    return render_template(
        "delete_user_confirmation.html",
        user=session.get("user"),
        target_user_id=user_id,
        target_username=user_row["username"],
        target_role=user_row["role"],
        target_email=user_row["email"],
        error_message=error_message
    )


@app.route("/doctor-key", methods=["GET", "POST"])
@require_role("doctor")
def doctor_key_entry():
    """
    Doctor must enter the correct access key to view patient details.
    """
    error_message = None
    
    if request.method == "POST":
        entered_key = request.form.get("doctor_access_key", "").strip()
        
        if entered_key == app.config["DOCTOR_ACCESS_KEY"]:
            session["doctor_key_verified"] = True
            log_action(session["user"]["username"], "doctor", "doctor_key_verified", request.path)
            return redirect(url_for("doctor_dashboard"))
        else:
            error_message = "❌ Incorrect doctor access key. Access denied."
            log_action(session["user"]["username"], "doctor", "failed_doctor_key_attempt", request.path)
    
    return render_template(
        "doctor_key_entry.html",
        user=session.get("user"),
        error_message=error_message
    )


@app.route("/patient-details-key/<int:patient_id>", methods=["GET", "POST"])
@require_role("doctor")
def patient_details_key_entry(patient_id):
    """
    Doctor must enter key to view full patient details (email, etc.)
    """
    if not session.get("doctor_key_verified"):
        return redirect(url_for("doctor_key_entry"))
    
    # Get patient info
    conn = get_db()
    patient_row = conn.execute("SELECT id, username, email, first_name, last_name FROM users WHERE id = ? AND role = 'patient'", (patient_id,)).fetchone()
    
    if not patient_row:
        return "Patient not found", 404
    
    error_message = None
    
    if request.method == "POST":
        entered_key = request.form.get("patient_details_key", "").strip()
        
        if entered_key == app.config["PATIENT_DETAILS_KEY"]:
            # Set verification for this specific patient in session
            if "patient_details_verified" not in session:
                session["patient_details_verified"] = {}
            session["patient_details_verified"][str(patient_id)] = True
            session.modified = True
            log_action(session["user"]["username"], "doctor", f"verified_patient_details_{patient_id}", request.path)
            return redirect(url_for("view_patient_details", patient_id=patient_id))
        else:
            error_message = "❌ Incorrect details access key. Access denied."
            log_action(session["user"]["username"], "doctor", f"failed_patient_details_key_{patient_id}", request.path)
    
    return render_template(
        "patient_details_key_entry.html",
        user=session.get("user"),
        patient_name=f"{patient_row['first_name']} {patient_row['last_name']}" if patient_row['first_name'] and patient_row['last_name'] else patient_row['username'],
        patient_id=patient_id,
        error_message=error_message
    )


@app.route("/patient-details/<int:patient_id>")
@require_role("doctor")
def view_patient_details(patient_id):
    """
    Display full patient details (only if key verified)
    """
    if not session.get("doctor_key_verified"):
        return redirect(url_for("doctor_key_entry"))
    
    # Check if doctor has verified details access for this patient
    patient_details_verified = session.get("patient_details_verified", {})
    if str(patient_id) not in patient_details_verified:
        return redirect(url_for("patient_details_key_entry", patient_id=patient_id))
    
    # Get patient details
    conn = get_db()
    patient_row = conn.execute("SELECT id, username, email, first_name, last_name FROM users WHERE id = ? AND role = 'patient'", (patient_id,)).fetchone()
    
    if not patient_row:
        return "Patient not found", 404
    
    return render_template(
        "patient_details_view.html",
        user=session.get("user"),
        patient_id=patient_row["id"],
        patient_username=patient_row["username"],
        patient_email=patient_row["email"] or "N/A",
        patient_first_name=patient_row["first_name"] or "N/A",
        patient_last_name=patient_row["last_name"] or "N/A",
        session_id=session.get("user", {}).get("username", "unknown")
    )


@app.route('/report-key/<int:report_id>', methods=['GET', 'POST'])
@require_role('patient')
def report_key_entry(report_id: int):
    """
    Patient must enter the report download key to download a report.
    """
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))

    # Find report and verify ownership
    rep = next((r for r in REPORTS_STORE if r['id'] == report_id), None)
    if not rep or rep['patient_id'] != _get_patient_id(user['username']):
        abort(404)

    error_message = None
    if request.method == 'POST':
        entered_key = request.form.get('report_download_key', '').strip()
        if entered_key == app.config.get('REPORT_DOWNLOAD_KEY'):
            # Log verification
            db = get_db()
            security_logger = SecurityLogger(db)
            patient_id = _get_patient_id(user['username'])
            security_logger.log_security_event(
                user['username'], patient_id, 'report_download_verified', 'low', request.remote_addr, None,
                {'report_id': report_id}
            )

            return redirect(url_for('download_report', report_id=report_id, _key=entered_key))
        else:
            error_message = '❌ Incorrect download access key. Access denied.'
            # Log failed attempt
            db = get_db()
            security_logger = SecurityLogger(db)
            patient_id = _get_patient_id(user['username'])
            security_logger.log_security_event(
                user['username'], patient_id, 'failed_report_download_key', 'medium', request.remote_addr, None,
                {'report_id': report_id}
            )

    return render_template('patient_report_key_entry.html', user=user, report_title=rep.get('title', rep.get('filename')), report_id=report_id, error_message=error_message)


@app.route("/doctor")
@require_role("doctor")
def doctor_dashboard():
    # Check if doctor has verified the key
    if not session.get("doctor_key_verified"):
        return redirect(url_for("doctor_key_entry"))
    
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
        upload_error=session.pop("upload_error", None),
        upload_success=session.pop("upload_success", None),
    )


@app.route("/patient")
@require_role("patient")
def patient_dashboard():
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
        log_action(user["username"], user["role"], "upload_report_attempt", request.path)

    # Require doctor access key (per-upload)
    if not session.get("doctor_key_verified"):
        return redirect(url_for("doctor_key_entry"))

    report_key = request.form.get("report_access_key", "").strip()
    if report_key != app.config.get("REPORT_UPLOAD_KEY"):
        # Log and notify
        db = get_db()
        security_logger = SecurityLogger(db)
        doctor_id = _get_user_id(user["username"]) if user else None
        security_logger.log_security_event(
            user["username"] if user else "unknown",
            doctor_id,
            "failed_report_upload_key",
            "medium",
            request.remote_addr,
            None,
            {"reason": "invalid_report_access_key"}
        )
        session["upload_error"] = "❌ Incorrect report access key. Upload denied."
        return redirect(url_for("doctor_dashboard"))

    patient_id = request.form.get("patient_id")
    file = request.files.get("report_file")

    # Basic validation
    if not file or file.filename == "":
        session["upload_error"] = "No file selected for upload."
        return redirect(url_for("doctor_dashboard"))

    # Allowed extensions
    allowed_ext = {"pdf", "jpg", "jpeg", "png"}
    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in allowed_ext:
        session["upload_error"] = "File type not allowed. Allowed: pdf, jpg, png."
        return redirect(url_for("doctor_dashboard"))

    # Ensure upload folder exists
    upload_folder = Path(app.config.get("REPORTS_FOLDER"))
    upload_folder.mkdir(parents=True, exist_ok=True)

    # Save file securely
    safe_name = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}_{user['username'] if user else 'unknown'}_{filename}"
    save_path = upload_folder / safe_name
    try:
        file.save(str(save_path))
    except Exception:
        session["upload_error"] = "Failed to save file. Try again." 
        return redirect(url_for("doctor_dashboard"))

    global REPORT_COUNTER
    try:
        pid = int(patient_id)
        REPORTS_STORE.append(
            {
                "id": REPORT_COUNTER,
                "patient_id": pid,
                "doctor": user["username"] if user else "doctor",
                "title": filename,
                "filename": safe_name,
                "date": datetime.now(timezone.utc).isoformat(),
                "flag": "normal",
                "path": str(save_path)
            }
        )
        REPORT_COUNTER += 1
        # Log success
        db = get_db()
        security_logger = SecurityLogger(db)
        doctor_id = _get_user_id(user["username"]) if user else None
        security_logger.log_security_event(
            user["username"] if user else "unknown",
            doctor_id,
            "report_uploaded",
            "low",
            request.remote_addr,
            None,
            {"patient_id": pid, "filename": safe_name}
        )
        session["upload_success"] = "✅ Report uploaded securely."
    except (TypeError, ValueError):
        session["upload_error"] = "Invalid patient selected."

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
    Secure download for patient reports - requires key every time.
    """
    user = session.get("user")
    rep = next((r for r in REPORTS_STORE if r["id"] == report_id), None)
    if not rep or not user or rep["patient_id"] != _get_patient_id(user["username"]):
        abort(404)

    # Always require key verification - redirect to key entry
    key = request.args.get('_key', '').strip()
    if not key or key != app.config.get('REPORT_DOWNLOAD_KEY'):
        # Redirect to key entry page
        return redirect(url_for("report_key_entry", report_id=report_id))

    # Serve the downloaded file if path exists (fallback to placeholder)
    file_path = rep.get("path")
    log_action(user["username"], user["role"], "download_report", request.path)
    if file_path:
        try:
            return send_file(file_path, as_attachment=True, download_name=rep.get('title', rep.get('filename')))
        except Exception:
            # Fallback text if send_file fails
            return f"Report {report_id} ({rep['filename']}) download is not available.", 200

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
    session.pop("admin_key_verified", None)  # Clear admin key verification
    session.pop("doctor_key_verified", None)  # Clear doctor key verification
    if user:
        log_action(user["username"], user["role"], "logout", request.path)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)

