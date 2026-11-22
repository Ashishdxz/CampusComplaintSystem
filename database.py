import sqlite3
import os
import uuid
import json
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime

# Base directory of the project
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def format_timestamp(ts):
    """
    Neatly formats timestamp strings from Supabase (ISO format) or SQLite
    without losing original date, time or timezone info.
    Example:
      '2026-11-20T00:10:00+00:00' -> '2026-11-20 00:10:00 (UTC)'
      '2026-11-19 15:57:40'       -> '2026-11-19 15:57:40'
    """
    if not ts:
        return ""
    if isinstance(ts, str):
        try:
            normalized = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is not None:
                tz_name = dt.tzname() or f"UTC{dt.strftime('%z')}"
                return dt.strftime(f"%Y-%m-%d %H:%M:%S ({tz_name})")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ts
    return str(ts)

def get_sqlite_path():
    """
    Returns the SQLite database path.
    Uses /tmp in serverless environments (e.g. Vercel) if SQLite is explicitly used.
    """
    if "DB_PATH" in os.environ:
        return os.environ["DB_PATH"]
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return "/tmp/complaints.db"
    return os.path.join(BASE_DIR, "complaints.db")

def is_supabase_enabled():
    """
    Returns True if Supabase credentials are configured in the environment.
    """
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_KEY", "").strip()
    return bool(url and key)

def get_supabase_url():
    """Returns normalized base URL for Supabase."""
    return os.environ.get("SUPABASE_URL", "").strip().rstrip("/")

def get_supabase_key():
    """Returns server-side Supabase key (service_role or general key)."""
    return os.environ.get("SUPABASE_KEY", "").strip()

def get_supabase_anon_key():
    """
    Returns the public anon key.
    Fails safely with a clear configuration error if SUPABASE_ANON_KEY is not configured.
    Strictly avoids falling back to SUPABASE_KEY to prevent using secret or service-role keys.
    """
    anon_key = os.environ.get("SUPABASE_ANON_KEY", "").strip()
    if not anon_key:
        raise RuntimeError(
            "Configuration error: 'SUPABASE_ANON_KEY' is not configured in environment variables. "
            "Supabase Auth operations require the public anon key."
        )
    return anon_key

def _supabase_request(endpoint, method="GET", data=None, params=None):
    """
    Executes an authenticated HTTP request to the Supabase PostgREST API
    using Python's standard library (urllib).
    Requires zero external dependencies.
    """
    base_url = get_supabase_url()
    api_key = get_supabase_key()

    url = f"{base_url}/rest/v1/{endpoint.lstrip('/')}"
    if params:
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"

    headers = {
        "apikey": api_key,
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        if method in ("POST", "PATCH"):
            headers["Prefer"] = "return=representation"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            resp_body = response.read().decode("utf-8")
            if resp_body:
                return json.loads(resp_body)
            return None
    except urllib.error.HTTPError as e:
        error_msg = e.read().decode("utf-8")
        print(f"Supabase HTTP Error {e.code}: {error_msg}")
        raise RuntimeError(f"Supabase API error ({e.code}): {error_msg}")
    except Exception as e:
        print(f"Supabase Connection Error: {e}")
        raise

def _supabase_auth_request(endpoint, method="POST", data=None, token=None, params=None):
    """
    Executes an authenticated HTTP request to Supabase GoTrue Auth API (/auth/v1/...).
    Uses standard library urllib without heavy external packages.
    """
    base_url = get_supabase_url()
    api_key = get_supabase_anon_key()

    url = f"{base_url}/auth/v1/{endpoint.lstrip('/')}"
    if params:
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"

    headers = {
        "apikey": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            resp_body = response.read().decode("utf-8")
            if resp_body:
                return json.loads(resp_body)
            return {}
    except urllib.error.HTTPError as e:
        raw_error = e.read().decode("utf-8")
        parsed_msg = f"Authentication error ({e.code})"
        try:
            err_json = json.loads(raw_error)
            parsed_msg = (
                err_json.get("msg")
                or err_json.get("error_description")
                or err_json.get("message")
                or parsed_msg
            )
        except Exception:
            pass
        raise RuntimeError(parsed_msg)
    except Exception as e:
        raise RuntimeError(f"Unable to reach authentication service: {e}")

def validate_user_id(user_id):
    """
    Validates that a user_id conforms to standard UUID format.
    Returns canonical normalized UUID string, or None if invalid.
    Prevents parameter injection or malformed identifiers.
    """
    if not user_id:
        return None
    try:
        return str(uuid.UUID(str(user_id).strip()))
    except (ValueError, AttributeError, TypeError):
        return None

def verify_supabase_token(access_token):
    """
    Cryptographically verifies a user's Supabase JWT access token by calling
    the Supabase Auth server endpoint GET /auth/v1/user.
    Never trusts client-provided claims without this server-side validation.
    Returns verified user dictionary on success, or None on failure.
    """
    if not access_token or not is_supabase_enabled():
        return None

    try:
        data = _supabase_auth_request("user", method="GET", token=access_token)
        if data and isinstance(data, dict) and "id" in data:
            return {
                "id": data.get("id"),
                "email": data.get("email"),
                "user_metadata": data.get("user_metadata", {}) or {},
                "confirmed_at": data.get("email_confirmed_at") or data.get("confirmed_at")
            }
        return None
    except Exception as e:
        print(f"Token verification check failed: {e}")
        return None

def supabase_auth_signup(email, password, full_name=None):
    """
    Registers a new student account using Supabase Auth.
    If email confirmation is active in Supabase, sends confirmation email.
    """
    payload = {
        "email": email.strip().lower(),
        "password": password
    }
    if full_name:
        payload["data"] = {"full_name": full_name.strip()}

    return _supabase_auth_request("signup", method="POST", data=payload)

def supabase_auth_login(email, password):
    """
    Authenticates a student using Email and Password via Supabase Auth GoTrue.
    Returns token dict containing access_token, refresh_token, and user object.
    """
    payload = {
        "email": email.strip().lower(),
        "password": password
    }
    return _supabase_auth_request("token?grant_type=password", method="POST", data=payload)

def supabase_auth_recover_password(email, redirect_url=None):
    """
    Initiates password recovery email flow via Supabase Auth.
    """
    payload = {"email": email.strip().lower()}
    params = {}
    if redirect_url:
        params["redirect_to"] = redirect_url
    return _supabase_auth_request("recover", method="POST", data=payload, params=params if params else None)

def supabase_auth_update_password(access_token, new_password):
    """
    Updates the password for an authenticated user using their verified access token.
    """
    payload = {"password": new_password}
    return _supabase_auth_request("user", method="PUT", data=payload, token=access_token)

def get_db_connection():
    """
    Creates and returns a connection to the local SQLite database.
    Retained for backward compatibility.
    """
    conn = sqlite3.connect(get_sqlite_path())
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes the database safely.
    If Supabase is enabled, this is a no-op (schema is already configured in Supabase).
    If SQLite is used locally, it ensures the complaints table exists without crashing
    and gracefully handles the user_id column.
    """
    if is_supabase_enabled():
        print("Using Supabase cloud database. SQLite local initialization skipped.")
        return

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS complaints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                is_anonymous INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT
            )
        """)
        # Ensure user_id column exists if complaints table pre-dated this update
        cursor.execute("PRAGMA table_info(complaints)")
        columns = [col[1] for col in cursor.fetchall()]
        if "user_id" not in columns:
            cursor.execute("ALTER TABLE complaints ADD COLUMN user_id TEXT")
        conn.commit()
        conn.close()
        print("Local SQLite database and 'complaints' table initialized successfully!")
    except Exception as e:
        print(f"Notice: SQLite init_db skipped or handled safely: {e}")

def db_insert_complaint(title, category, description, is_anonymous, user_id=None):
    """
    Inserts a new complaint and returns its auto-generated integer ID.
    Supports linking to an authenticated user's UUID (user_id).
    If user_id is None, it records as an anonymous guest complaint.
    """
    clean_user_id = validate_user_id(user_id) if user_id else None

    if is_supabase_enabled():
        payload = {
            "title": title,
            "category": category,
            "description": description,
            "is_anonymous": is_anonymous,
            "status": "Pending"
        }
        if clean_user_id:
            payload["user_id"] = clean_user_id
        res = _supabase_request("complaints", method="POST", data=payload)
        if res and isinstance(res, list) and len(res) > 0:
            return int(res[0]["id"])
        raise RuntimeError("Failed to retrieve generated ID from Supabase.")
    else:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO complaints (title, category, description, is_anonymous, status, user_id)
            VALUES (?, ?, ?, ?, 'Pending', ?)
        """, (title, category, description, is_anonymous, clean_user_id))
        conn.commit()
        new_id = cursor.lastrowid
        conn.close()
        return new_id

def db_get_complaint_by_id(complaint_id):
    """
    Fetches a single complaint by its primary key ID.
    Returns a dictionary or None with clean timestamp formatting.
    """
    if is_supabase_enabled():
        endpoint = f"complaints?id=eq.{int(complaint_id)}&select=*"
        res = _supabase_request(endpoint, method="GET")
        if res and isinstance(res, list) and len(res) > 0:
            item = dict(res[0])
            if "created_at" in item:
                item["created_at_raw"] = item["created_at"]
                item["created_at"] = format_timestamp(item["created_at"])
            return item
        return None
    else:
        conn = get_db_connection()
        row = conn.execute("SELECT * FROM complaints WHERE id = ?", (int(complaint_id),)).fetchone()
        conn.close()
        if row:
            item = dict(row)
            if "created_at" in item:
                item["created_at_raw"] = item["created_at"]
                item["created_at"] = format_timestamp(item["created_at"])
            return item
        return None

def db_get_all_complaints():
    """
    Fetches all complaints ordered newest first (by id DESC).
    Returns a list of dictionaries with clean timestamp formatting.
    """
    if is_supabase_enabled():
        endpoint = "complaints?order=id.desc&select=*"
        res = _supabase_request(endpoint, method="GET")
        items = res if (res and isinstance(res, list)) else []
    else:
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM complaints ORDER BY id DESC").fetchall()
        conn.close()
        items = [dict(r) for r in rows]

    formatted_list = []
    for raw in items:
        item = dict(raw)
        if "created_at" in item:
            item["created_at_raw"] = item["created_at"]
            item["created_at"] = format_timestamp(item["created_at"])
        formatted_list.append(item)
    return formatted_list

def db_get_complaints_by_user(user_id):
    """
    Fetches all complaints submitted by a specific authenticated user (by user_id).
    Validates user_id format and returns a list of dictionaries ordered newest first.
    """
    clean_user_id = validate_user_id(user_id)
    if not clean_user_id:
        return []

    if is_supabase_enabled():
        endpoint = f"complaints?user_id=eq.{clean_user_id}&order=id.desc&select=*"
        res = _supabase_request(endpoint, method="GET")
        items = res if (res and isinstance(res, list)) else []
    else:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT * FROM complaints WHERE user_id = ? ORDER BY id DESC",
            (clean_user_id,)
        ).fetchall()
        conn.close()
        items = [dict(r) for r in rows]

    formatted_list = []
    for raw in items:
        item = dict(raw)
        if "created_at" in item:
            item["created_at_raw"] = item["created_at"]
            item["created_at"] = format_timestamp(item["created_at"])
        formatted_list.append(item)
    return formatted_list

def db_update_complaint_status(complaint_id, new_status):
    """
    Updates the status of a complaint. Returns True if updated, False if not found.
    """
    if is_supabase_enabled():
        endpoint = f"complaints?id=eq.{int(complaint_id)}"
        payload = {"status": new_status}
        res = _supabase_request(endpoint, method="PATCH", data=payload)
        return bool(res and isinstance(res, list) and len(res) > 0)
    else:
        conn = get_db_connection()
        cursor = conn.cursor()
        row = cursor.execute("SELECT id FROM complaints WHERE id = ?", (int(complaint_id),)).fetchone()
        if not row:
            conn.close()
            return False
        cursor.execute("UPDATE complaints SET status = ? WHERE id = ?", (new_status, int(complaint_id)))
        conn.commit()
        conn.close()
        return True

if __name__ == "__main__":
    init_db()
