 -- SQLite schema and seed data
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS device_fingerprints;
DROP TABLE IF EXISTS security_logs;
DROP TABLE IF EXISTS logs;
DROP TABLE IF EXISTS appointments;
DROP TABLE IF EXISTS otp_tokens;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT CHECK (role IN ('admin','doctor','patient')) NOT NULL,
    email TEXT,
    first_name TEXT,
    last_name TEXT,
    is_verified INTEGER DEFAULT 0,
    last_login_ip TEXT,
    last_login_time TEXT,
    last_known_fingerprint TEXT
);

CREATE TABLE otp_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    otp_code TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    is_used INTEGER DEFAULT 0
);

CREATE TABLE appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    doctor_id INTEGER NOT NULL,
    scheduled_at TEXT NOT NULL,
    reason TEXT,
    status TEXT DEFAULT 'pending',
    created_at TEXT NOT NULL,
    FOREIGN KEY (patient_id) REFERENCES users(id),
    FOREIGN KEY (doctor_id) REFERENCES users(id)
);

CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    user TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    endpoint TEXT NOT NULL
);

CREATE TABLE device_fingerprints (
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
);

CREATE TABLE login_attempts (
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
);

CREATE TABLE security_logs (
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
);

-- All three users share the same password: password@123
INSERT INTO users (username, password_hash, role, email, is_verified) VALUES
('Tharun Admin', 'scrypt:32768:8:1$u2F8w3Ie918HeqMx$cba50b4b0abe7aa3e23d1b758dbd9231c17860f31a79785ad2fde8936ed787d51543ce97417046c31f8284791b6b9e636a54de17f00f59102b96eb782fdf05a4', 'admin', NULL, 1),
('doctor1', 'scrypt:32768:8:1$u2F8w3Ie918HeqMx$cba50b4b0abe7aa3e23d1b758dbd9231c17860f31a79785ad2fde8936ed787d51543ce97417046c31f8284791b6b9e636a54de17f00f59102b96eb782fdf05a4', 'doctor', 'doctor1@hospital.com', 1),
('patient1', 'scrypt:32768:8:1$u2F8w3Ie918HeqMx$cba50b4b0abe7aa3e23d1b758dbd9231c17860f31a79785ad2fde8936ed787d51543ce97417046c31f8284791b6b9e636a54de17f00f59102b96eb782fdf05a4', 'patient', 'patient1@example.com', 1);

