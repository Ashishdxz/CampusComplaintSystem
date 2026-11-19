import sqlite3
import os

# Base directory of the project
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# On local development, uses complaints.db in the project directory.
# In serverless environments (like Vercel /tmp), can be configured via DB_PATH.
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "complaints.db"))

def get_db_connection():
    """
    Creates and returns a connection to the SQLite database.
    row_factory = sqlite3.Row allows us to access columns by their name
    like a Python dictionary (e.g., complaint['title']).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Creates the 'complaints' table if it does not already exist.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # SQL command to create the complaints table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            is_anonymous INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    print("Database and 'complaints' table initialized successfully!")

if __name__ == "__main__":
    init_db()
