import os
import hmac
import time
import re
from datetime import timedelta
from functools import wraps
from collections import deque
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from database import (
    init_db,
    get_db_connection,
    db_insert_complaint,
    db_get_complaint_by_id,
    db_get_all_complaints,
    db_get_complaints_by_user,
    db_update_complaint_status,
    is_supabase_enabled,
    supabase_auth_signup,
    supabase_auth_login,
    supabase_auth_recover_password,
    supabase_auth_update_password,
    verify_supabase_token,
    validate_user_id,
    get_supabase_url
)

def load_env():
    """Load configuration from a local .env file if it exists."""
    env_file = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_file):
        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if key and key not in os.environ:
                        os.environ[key] = val

# Load .env variables at startup
load_env()

# Initialize the Flask application
app = Flask(__name__)

# Secret key used for session management and flash messages
app.secret_key = os.environ.get("SECRET_KEY", "campus-complaint-secret-key-change-in-production")

# Session Cookie Security Configuration
# Protects against XSS cookie theft and CSRF while allowing OAuth redirects
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=not app.debug and not os.environ.get("FLASK_DEBUG"),
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

# Admin credentials must be configured via environment variables (no default credentials)
ADMIN_USERNAME_ENV = "ADMIN_USERNAME"
ADMIN_PASSWORD_ENV = "ADMIN_PASSWORD"

# In-memory sliding window history for tracking rate-limiting (without trusting spoofable headers)
TRACK_RATE_LIMIT = 15     # Max lookups allowed
TRACK_RATE_WINDOW = 60    # per 60 seconds
_ip_track_history = {}    # {ip_str: deque([timestamp, ...])}

def is_tracking_rate_limited():
    """
    Evaluates whether the current tracking request exceeds rate limits.
    Combines tamper-proof signed session history with server-derived remote_addr.
    Never relies on spoofable client HTTP headers like X-Forwarded-For.
    """
    now = time.time()

    # 1. Tamper-proof signed session check
    session_history = session.get("track_history", [])
    session_history = [t for t in session_history if (now - t) < TRACK_RATE_WINDOW]
    if len(session_history) >= TRACK_RATE_LIMIT:
        session["track_history"] = session_history
        return True

    # 2. Server-derived remote_addr check
    ip = request.remote_addr or "unknown"
    ip_history = _ip_track_history.get(ip)
    if ip_history is None:
        ip_history = deque()
        _ip_track_history[ip] = ip_history

    while ip_history and (now - ip_history[0]) > TRACK_RATE_WINDOW:
        ip_history.popleft()

    if len(ip_history) >= TRACK_RATE_LIMIT:
        return True

    # Record the attempt in both buckets
    session_history.append(now)
    session["track_history"] = session_history
    ip_history.append(now)
    return False

def login_required(f):
    """
    Decorator to protect routes requiring authenticated student access.
    Validates that a verified user session exists on the server side.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = session.get("user")
        if not user or not user.get("id"):
            flash("Please log in to access this page.", "error")
            return redirect(url_for("user_login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function

def is_valid_email(email):
    """Simple syntax validation for email format."""
    if not email or not isinstance(email, str):
        return False
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email.strip()))

# Context processor to make current_user and is_admin globally accessible in templates
@app.context_processor
def inject_auth_context():
    return {
        "current_user": session.get("user"),
        "is_admin": bool(session.get("is_admin")),
        "supabase_url": get_supabase_url()
    }

# Ensure database and table exist at startup
init_db()

# ====================================================================
# MANDATORY AUTHENTICATION ENFORCEMENT
# ====================================================================

# Endpoints and path prefixes accessible without student authentication
PUBLIC_ENDPOINTS = {
    "user_login",
    "signup",
    "forgot_password",
    "reset_password",
    "auth_callback",
    "auth_session",
    "user_logout",
    "login",            # Admin login
    "admin_dashboard",  # Has its own admin session validation
    "update_status",    # Has its own admin session validation
    "logout",           # Admin logout
    "static"
}

@app.before_request
def require_mandatory_authentication():
    """
    Enforces mandatory Google / student authentication across the website.
    Any unauthenticated visitor opening the website or attempting direct URL access
    to complaint submission or tracking is immediately redirected to /user-login.
    Preserves admin login and static assets.
    """
    # 1. Allow static assets and favicon
    if request.path.startswith("/static/") or request.path == "/favicon.ico":
        return None

    # 2. Allow whitelisted authentication endpoints and admin routes
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None

    public_prefixes = (
        "/user-login",
        "/signup",
        "/forgot-password",
        "/reset-password",
        "/auth/callback",
        "/auth/session",
        "/user/logout",
        "/login",
        "/admin",
        "/logout",
    )
    if any(request.path == p or request.path.startswith(p + "/") for p in public_prefixes):
        return None

    # 3. Allow active admin sessions to navigate without student auth
    if session.get("is_admin"):
        return None

    # 4. Enforce Student Authentication for all other pages
    user = session.get("user")
    if not user or not user.get("id"):
        # Prevent redirect loops if already on user_login
        if request.path == url_for("user_login"):
            return None
        # Notify user when directly accessing inner pages
        if request.path != "/":
            flash("Please sign in with Google to continue.", "info")
            return redirect(url_for("user_login", next=request.path))
        return redirect(url_for("user_login"))

    return None

# ====================================================================
# PUBLIC & COMPLAINT ROUTES
# ====================================================================

# Route: Home page with the complaint submission form
@app.route("/")
def home():
    return render_template("index.html")

# Route: Handle complaint form submission (POST)
@app.route("/submit", methods=["POST"])
def submit_complaint():
    # 1. Retrieve submitted form data
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    description = request.form.get("description", "").strip()
    
    # Checkbox returns 'on' if checked; otherwise None. We store 1 for anonymous, 0 otherwise.
    is_anonymous = 1 if request.form.get("is_anonymous") else 0

    # 2. Server-side validation: Check that all required fields are filled
    if not title or not category or not description:
        flash("Please fill in all required fields (Title, Category, and Description).", "error")
        return redirect(url_for("home"))

    # 3. Determine user_id: If authenticated student, link complaint; otherwise None (guest)
    user_id = None
    curr_user = session.get("user")
    if curr_user and curr_user.get("id"):
        user_id = validate_user_id(curr_user["id"])

    # 4. Insert complaint record into database (Supabase or SQLite fallback)
    try:
        complaint_id = db_insert_complaint(title, category, description, is_anonymous, user_id=user_id)
    except Exception as e:
        print(f"Error submitting complaint: {e}")
        flash("We encountered an issue submitting your complaint. Please try again in a moment.", "error")
        return redirect(url_for("home"))

    # 5. Generate a unique, student-friendly Reference ID (e.g. CMP-0001)
    reference_id = f"CMP-{complaint_id:04d}"

    # 6. Render the confirmation page with the Reference ID
    return render_template(
        "success.html",
        reference_id=reference_id,
        complaint_id=complaint_id,
        title=title,
        category=category
    )

# Route: Track complaint status by Reference ID (Minimal Data Disclosure + Rate Limiting)
@app.route("/track", methods=["GET", "POST"])
def track():
    ref_query = request.args.get("ref", "").strip() or request.form.get("ref", "").strip()
    complaint = None
    error_message = None

    if ref_query:
        # Rate limit enforcement: Prevent automated ID enumeration
        if is_tracking_rate_limited():
            return render_template(
                "track.html",
                complaint=None,
                error_message="Too many tracking requests. Please wait a minute before searching again.",
                ref_query=ref_query
            ), 429

        # Normalize input: strip "CMP-", "cmp-", and whitespace
        cleaned_id = ref_query.upper().replace("CMP-", "").replace("CMP", "").strip()

        if cleaned_id.isdigit():
            complaint_id = int(cleaned_id)
            try:
                row = db_get_complaint_by_id(complaint_id)
            except Exception as e:
                print(f"Error retrieving complaint #{complaint_id}: {e}")
                error_message = "Unable to retrieve complaint details at this time. Please try again later."
                row = None

            if row:
                # MINIMAL DATA DISCLOSURE: Exposes only status-tracking metadata.
                # Description, user_id, and personal identity are DELIBERATELY omitted.
                complaint = {
                    "reference_id": f"CMP-{row['id']:04d}",
                    "title": row["title"],
                    "category": row["category"],
                    "status": row["status"],
                    "created_at": row["created_at"]
                }
            elif not error_message:
                error_message = f"No complaint found matching Reference ID '{ref_query.upper()}'. Please verify the number and try again."
        else:
            error_message = f"Invalid format '{ref_query}'. Reference ID should look like CMP-0001 or 1."

    return render_template(
        "track.html",
        complaint=complaint,
        error_message=error_message,
        ref_query=ref_query
    )

# ====================================================================
# STUDENT AUTHENTICATION ROUTES (SUPABASE AUTH)
# ====================================================================

# Route: Student Registration (Sign Up)
@app.route("/signup", methods=["GET", "POST"])
def signup():
    # If already logged in as a student, redirect to home
    if session.get("user"):
        return redirect(url_for("home"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Input validation
        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("signup.html"), 400

        if not is_valid_email(email):
            flash("Please enter a valid email address.", "error")
            return render_template("signup.html"), 400

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return render_template("signup.html"), 400

        if password != confirm_password:
            flash("Passwords do not match. Please re-enter.", "error")
            return render_template("signup.html"), 400

        try:
            res = supabase_auth_signup(email, password, full_name=full_name)
            user_data = res.get("user") if isinstance(res, dict) else None

            # If Supabase has email confirmation enabled
            identities = user_data.get("identities", []) if user_data else []
            if user_data and not user_data.get("email_confirmed_at") and not res.get("session"):
                flash(
                    "Registration successful! A verification email has been sent to your inbox. "
                    "Please verify your email before logging in.",
                    "success"
                )
                return redirect(url_for("user_login"))

            # If auto-confirmed or session provided immediately
            if res.get("session") and res["session"].get("access_token"):
                verified = verify_supabase_token(res["session"]["access_token"])
                if verified and verified.get("id"):
                    session["user"] = {
                        "id": verified["id"],
                        "email": verified["email"],
                        "name": verified.get("user_metadata", {}).get("full_name") or verified["email"].split("@")[0]
                    }
                    flash("Welcome to Campus Complaint System!", "success")
                    return redirect(url_for("my_complaints"))

            flash("Registration successful! Please log in to continue.", "success")
            return redirect(url_for("user_login"))
        except Exception as e:
            flash(str(e), "error")
            return render_template("signup.html"), 400

    return render_template("signup.html")

# Route: Student Login
@app.route("/user-login", methods=["GET", "POST"])
def user_login():
    # If already logged in, redirect directly to home
    if session.get("user"):
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter both email and password.", "error")
            return render_template("user_login.html"), 400

        try:
            res = supabase_auth_login(email, password)
            access_token = res.get("access_token")

            # Server-side token verification before establishing session
            verified_user = verify_supabase_token(access_token) if access_token else None
            if not verified_user or not verified_user.get("id"):
                flash("Authentication failed. Unable to verify user session.", "error")
                return render_template("user_login.html"), 401

            clean_user_id = validate_user_id(verified_user["id"])
            if not clean_user_id:
                flash("Invalid user identifier received from auth service.", "error")
                return render_template("user_login.html"), 400

            # Establish authenticated student session (Never sets is_admin)
            session["user"] = {
                "id": clean_user_id,
                "email": verified_user["email"],
                "name": verified_user.get("user_metadata", {}).get("full_name") or verified_user["email"].split("@")[0]
            }

            flash(f"Welcome back, {session['user']['name']}!", "success")

            # Safe redirect handling (prevents open redirects)
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/") and not next_url.startswith("//") and next_url != url_for("user_login"):
                return redirect(next_url)
            return redirect(url_for("home"))
        except Exception as e:
            flash(str(e), "error")
            return render_template("user_login.html"), 401

    return render_template("user_login.html")

# Route: Student Logout
@app.route("/user/logout")
def user_logout():
    # Safely clear student authentication state and related temporary tracking history
    # Leaves admin session (is_admin, admin_user) completely untouched and intact
    session.pop("user", None)
    session.pop("track_history", None)
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("user_login"))

# Route: Forgot Password (Initiate recovery email)
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if session.get("user"):
        return redirect(url_for("my_complaints"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email or not is_valid_email(email):
            flash("Please enter a valid email address.", "error")
            return render_template("forgot_password.html"), 400

        try:
            redirect_target = url_for("reset_password", _external=True)
            supabase_auth_recover_password(email, redirect_url=redirect_target)
            flash("If an account exists with that email, a password reset link has been sent. Please check your inbox.", "success")
            return redirect(url_for("user_login"))
        except Exception as e:
            flash(str(e), "error")
            return render_template("forgot_password.html"), 400

    return render_template("forgot_password.html")

# Route: Reset Password (Complete recovery flow)
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        access_token = request.form.get("access_token", "").strip()
        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not access_token:
            flash("Missing or expired reset session. Please request a new recovery link.", "error")
            return redirect(url_for("forgot_password"))

        if len(new_password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return render_template("reset_password.html", access_token=access_token), 400

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html", access_token=access_token), 400

        # Verify token server-side before updating password
        verified_user = verify_supabase_token(access_token)
        if not verified_user or not verified_user.get("id"):
            flash("Invalid or expired password reset token. Please request a new link.", "error")
            return redirect(url_for("forgot_password"))

        try:
            supabase_auth_update_password(access_token, new_password)
            flash("Your password has been reset successfully! Please log in with your new password.", "success")
            return redirect(url_for("user_login"))
        except Exception as e:
            flash(str(e), "error")
            return render_template("reset_password.html", access_token=access_token), 400

    return render_template("reset_password.html")

# Route: Google OAuth / Email Callback Handler (Client bridge page)
@app.route("/auth/callback")
def auth_callback():
    return render_template("auth_callback.html")

def get_allowed_origins():
    """
    Derives allowed origins dynamically for cross-origin protection.
    Includes request.host_url, configured APP_URL or VERCEL_URL if set.
    Never hardcodes incorrect production domains.
    """
    allowed = set()
    host_url = request.host_url.rstrip("/")
    if host_url:
        allowed.add(host_url)
        if host_url.startswith("http://"):
            allowed.add("https://" + host_url[7:])
        elif host_url.startswith("https://"):
            allowed.add("http://" + host_url[8:])

    forwarded_proto = request.headers.get("X-Forwarded-Proto")
    host = request.host
    if forwarded_proto and host:
        allowed.add(f"{forwarded_proto}://{host}".rstrip("/"))

    app_url = os.environ.get("APP_URL", "").strip().rstrip("/")
    if app_url:
        allowed.add(app_url)

    vercel_url = os.environ.get("VERCEL_URL", "").strip().rstrip("/")
    if vercel_url:
        allowed.add(f"https://{vercel_url}")

    # 5. Localhost fallbacks for development/testing if on local loopback
    if "localhost" in request.host or "127.0.0.1" in request.host or app.debug or os.environ.get("FLASK_DEBUG"):
        allowed.add("http://localhost:5000")
        allowed.add("http://127.0.0.1:5000")
        allowed.add("http://localhost")
        allowed.add("http://127.0.0.1")

    return allowed

def is_valid_request_origin():
    """
    Validates that a POST request originated from this application.
    Checks Origin and Referer headers against allowed application origins.
    Rejects unauthorized cross-origin requests.
    """
    allowed = get_allowed_origins()

    origin = request.headers.get("Origin", "").strip().rstrip("/")
    if origin:
        return origin in allowed

    referer = request.headers.get("Referer", "").strip()
    if referer:
        return any(referer.startswith(f"{orig}/") or referer == orig for orig in allowed)

    return False

# Route: Establish Server Session from Verified Token (POST JSON)
@app.route("/auth/session", methods=["POST"])
def auth_session():
    """
    Receives access_token from client-side Google OAuth or Supabase JS client.
    Enforces strict Origin validation to reject cross-origin requests.
    Never trusts client payload: strictly validates access_token with Supabase Auth server.
    """
    if not is_valid_request_origin():
        return jsonify({"success": False, "error": "Cross-origin request forbidden."}), 403

    data = request.get_json(silent=True) or {}
    access_token = data.get("access_token", "").strip()

    if not access_token:
        return jsonify({"success": False, "error": "Missing access token."}), 400

    verified_user = verify_supabase_token(access_token)
    if not verified_user or not verified_user.get("id"):
        return jsonify({"success": False, "error": "Invalid, expired, or untrusted session token."}), 401

    clean_user_id = validate_user_id(verified_user["id"])
    if not clean_user_id:
        return jsonify({"success": False, "error": "Invalid user identifier."}), 400

    # Establish authenticated student session (Never sets is_admin)
    session["user"] = {
        "id": clean_user_id,
        "email": verified_user["email"],
        "name": verified_user.get("user_metadata", {}).get("full_name") or verified_user["email"].split("@")[0]
    }

    return jsonify({"success": True, "redirect": url_for("home")})

# ====================================================================
# PROTECTED STUDENT DASHBOARD & PROFILE ROUTES
# ====================================================================

# Route: My Complaints (Protected user dashboard)
@app.route("/my-complaints")
@login_required
def my_complaints():
    # Uses STRICTLY the verified session user ID, never a client-supplied parameter
    user_id = session["user"]["id"]

    try:
        complaints = db_get_complaints_by_user(user_id)
    except Exception as e:
        print(f"Error loading user complaints: {e}")
        flash("Unable to load your complaints at this time. Please refresh.", "error")
        complaints = []

    # Calculate statistics for user
    total_count = len(complaints)
    pending_count = sum(1 for c in complaints if c.get("status") in ["Pending", "Pending Review"])
    in_progress_count = sum(1 for c in complaints if c.get("status") in ["In Progress", "In Review"])
    resolved_count = sum(1 for c in complaints if c.get("status") == "Resolved")

    return render_template(
        "my_complaints.html",
        complaints=complaints,
        total_count=total_count,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        resolved_count=resolved_count
    )

# Route: Student Profile (Protected account view)
@app.route("/profile")
@login_required
def profile():
    user_id = session["user"]["id"]
    try:
        complaints = db_get_complaints_by_user(user_id)
        total_complaints = len(complaints)
    except Exception:
        total_complaints = 0

    return render_template(
        "profile.html",
        user=session["user"],
        total_complaints=total_complaints
    )

# ====================================================================
# ADMIN ROUTES (COMPLETELY ISOLATED FROM STUDENT AUTH)
# ====================================================================

# Route: Admin Login (GET to display form, POST to authenticate)
@app.route("/login", methods=["GET", "POST"])
def login():
    # If already logged in as admin, redirect directly to admin dashboard
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        expected_username = os.environ.get(ADMIN_USERNAME_ENV)
        expected_password = os.environ.get(ADMIN_PASSWORD_ENV)

        if not expected_username or not expected_password:
            flash("Admin credentials are not configured on this system.", "error")
            return render_template("login.html"), 500

        # Constant-time comparison prevents timing attacks
        username_valid = hmac.compare_digest(username.encode("utf-8"), expected_username.encode("utf-8"))
        password_valid = hmac.compare_digest(password.encode("utf-8"), expected_password.encode("utf-8"))

        if username_valid and password_valid:
            session["is_admin"] = True
            session["admin_user"] = username
            flash("Welcome to the Admin Dashboard!", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid username or password. Please try again.", "error")
            return render_template("login.html"), 401

    return render_template("login.html")

# Route: Admin Dashboard (Protected route)
@app.route("/admin")
def admin_dashboard():
    # Protect dashboard route: verify admin session
    if not session.get("is_admin"):
        flash("Access denied. Please log in to view the Admin Dashboard.", "error")
        return redirect(url_for("login"))

    try:
        complaints = db_get_all_complaints()
    except Exception as e:
        print(f"Error loading complaints for admin dashboard: {e}")
        flash("Unable to load complaints from the database at this time. Please refresh or try again.", "error")
        complaints = []

    # Calculate statistics
    total_count = len(complaints)
    pending_count = sum(1 for c in complaints if c["status"] in ["Pending", "Pending Review"])
    in_progress_count = sum(1 for c in complaints if c["status"] in ["In Progress", "In Review"])
    resolved_count = sum(1 for c in complaints if c["status"] == "Resolved")

    return render_template(
        "admin.html",
        complaints=complaints,
        total_count=total_count,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        resolved_count=resolved_count
    )

# Route: Admin Update Complaint Status (Protected POST)
@app.route("/admin/update-status", methods=["POST"])
def update_status():
    if not session.get("is_admin"):
        flash("Access denied. Please log in to update complaint status.", "error")
        return redirect(url_for("login"))

    complaint_id = request.form.get("complaint_id", "").strip()
    new_status = request.form.get("status", "").strip()

    valid_statuses = ["Pending", "In Progress", "Resolved"]
    if new_status not in valid_statuses:
        flash("Invalid status selected. Allowed: Pending, In Progress, Resolved.", "error")
        return redirect(url_for("admin_dashboard"))

    if not complaint_id.isdigit():
        flash("Invalid complaint ID.", "error")
        return redirect(url_for("admin_dashboard"))

    try:
        success = db_update_complaint_status(int(complaint_id), new_status)
    except Exception as e:
        print(f"Error updating status for complaint #{complaint_id}: {e}")
        flash("An error occurred while updating the complaint status. Please try again.", "error")
        return redirect(url_for("admin_dashboard"))

    if not success:
        flash(f"Complaint ID #{complaint_id} not found.", "error")
        return redirect(url_for("admin_dashboard"))

    flash(f"Complaint CMP-{int(complaint_id):04d} status updated to '{new_status}' successfully!", "success")
    return redirect(url_for("admin_dashboard"))

# Route: Admin Logout
@app.route("/logout")
def logout():
    session.pop("is_admin", None)
    session.pop("admin_user", None)
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))

# Run the local development server when executed directly
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, port=port)
