import os
import hmac
from flask import Flask, render_template, request, redirect, url_for, flash, session
from database import init_db, get_db_connection

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
# Reads from environment variable if set, otherwise uses a default for local development
app.secret_key = os.environ.get("SECRET_KEY", "campus-complaint-secret-key-change-in-production")

# Admin credentials must be configured via environment variables (no default credentials)
ADMIN_USERNAME_ENV = "ADMIN_USERNAME"
ADMIN_PASSWORD_ENV = "ADMIN_PASSWORD"

# Ensure the database and complaints table exist when the app starts
init_db()

# Route: Home page with the student complaint submission form
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

    # 3. Insert complaint record into SQLite database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO complaints (title, category, description, is_anonymous, status)
        VALUES (?, ?, ?, ?, 'Pending')
    """, (title, category, description, is_anonymous))
    conn.commit()

    # Get the auto-incremented primary key of the new complaint
    complaint_id = cursor.lastrowid
    conn.close()

    # 4. Generate a unique, student-friendly Reference ID (e.g. CMP-0001)
    reference_id = f"CMP-{complaint_id:04d}"

    # 5. Render the confirmation page with the Reference ID
    return render_template(
        "success.html",
        reference_id=reference_id,
        complaint_id=complaint_id,
        title=title,
        category=category
    )

# Route: Track complaint status by Reference ID (GET and POST)
@app.route("/track", methods=["GET", "POST"])
def track():
    # Accept Reference ID from either URL parameter (?ref=CMP-0001) or form POST
    ref_query = request.args.get("ref", "").strip() or request.form.get("ref", "").strip()
    complaint = None
    error_message = None

    if ref_query:
        # Normalize input: strip "CMP-", "cmp-", and spaces so users can enter "CMP-0001" or just "1"
        cleaned_id = ref_query.upper().replace("CMP-", "").replace("CMP", "").strip()

        if cleaned_id.isdigit():
            complaint_id = int(cleaned_id)
            conn = get_db_connection()
            row = conn.execute("SELECT * FROM complaints WHERE id = ?", (complaint_id,)).fetchone()
            conn.close()

            if row:
                complaint = {
                    "id": row["id"],
                    "reference_id": f"CMP-{row['id']:04d}",
                    "title": row["title"],
                    "category": row["category"],
                    "description": row["description"],
                    "status": row["status"],
                    "created_at": row["created_at"],
                    "is_anonymous": row["is_anonymous"]
                }
            else:
                error_message = f"No complaint found matching Reference ID '{ref_query.upper()}'. Please check your ID and try again."
        else:
            error_message = f"Invalid format '{ref_query}'. Reference ID should look like CMP-0001 or 1."

    return render_template(
        "track.html",
        complaint=complaint,
        error_message=error_message,
        ref_query=ref_query
    )

# Route: Admin Login (GET to display form, POST to authenticate)
@app.route("/login", methods=["GET", "POST"])
def login():
    # If already logged in, redirect directly to admin dashboard
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        expected_username = os.environ.get(ADMIN_USERNAME_ENV)
        expected_password = os.environ.get(ADMIN_PASSWORD_ENV)

        # Do not allow login if admin credentials have not been configured
        if not expected_username or not expected_password:
            flash("Admin credentials are not configured on this system. Please set the ADMIN_USERNAME and ADMIN_PASSWORD environment variables.", "error")
            return render_template("login.html"), 500

        # Secure comparison using UTF-8 encoded bytes to support non-ASCII characters and prevent timing attacks
        username_valid = hmac.compare_digest(username.encode("utf-8"), expected_username.encode("utf-8"))
        password_valid = hmac.compare_digest(password.encode("utf-8"), expected_password.encode("utf-8"))

        if username_valid and password_valid:
            # Set session variables
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
    # Protect dashboard route: verify session
    if not session.get("is_admin"):
        flash("Access denied. Please log in to view the Admin Dashboard.", "error")
        return redirect(url_for("login"))

    conn = get_db_connection()
    complaints = conn.execute("SELECT * FROM complaints ORDER BY id DESC").fetchall()
    conn.close()

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
    # Protect route: verify active admin session
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

    conn = get_db_connection()
    cursor = conn.cursor()
    row = cursor.execute("SELECT id FROM complaints WHERE id = ?", (int(complaint_id),)).fetchone()
    if not row:
        conn.close()
        flash(f"Complaint ID #{complaint_id} not found.", "error")
        return redirect(url_for("admin_dashboard"))

    cursor.execute("UPDATE complaints SET status = ? WHERE id = ?", (new_status, int(complaint_id)))
    conn.commit()
    conn.close()

    flash(f"Complaint CMP-{int(complaint_id):04d} status updated to '{new_status}' successfully!", "success")
    return redirect(url_for("admin_dashboard"))

# Route: Admin Logout
@app.route("/logout")
def logout():
    session.pop("is_admin", None)
    session.pop("admin_user", None)
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))

# Run the local development server when this file is executed directly
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, port=port)
