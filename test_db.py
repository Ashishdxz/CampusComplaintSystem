"""
Quick test script to verify that our SQLite database can:
1. Insert a new complaint (INSERT)
2. Retrieve the complaint by ID (SELECT)
3. Access fields like a Python dictionary
"""

from database import get_db_connection

def test_database():
    conn = get_db_connection()
    cursor = conn.cursor()

    print("--- 1. Testing Database Insertion ---")
    # Using parameterized queries (?) protects against SQL Injection
    cursor.execute("""
        INSERT INTO complaints (title, category, description, is_anonymous, status)
        VALUES (?, ?, ?, ?, ?)
    """, (
        "Wi-Fi not working in Library 2nd floor",
        "Wi-Fi",
        "The internet disconnects repeatedly every 5 minutes.",
        1,
        "Pending"
    ))
    conn.commit()

    sample_id = cursor.lastrowid
    print(f"✔ Success: Sample complaint inserted with ID: {sample_id}")

    print("\n--- 2. Testing Database Retrieval ---")
    row = cursor.execute("SELECT * FROM complaints WHERE id = ?", (sample_id,)).fetchone()

    print("✔ Successfully fetched row from SQLite:")
    print(f"   ID:           {row['id']}")
    print(f"   Title:        {row['title']}")
    print(f"   Category:     {row['category']}")
    print(f"   Description:  {row['description']}")
    print(f"   Is Anonymous: {bool(row['is_anonymous'])}")
    print(f"   Status:       {row['status']}")
    print(f"   Created Date: {row['created_at']}")

    print("\n--- 3. Cleaning Up Test Data ---")
    cursor.execute("DELETE FROM complaints WHERE id = ?", (sample_id,))
    conn.commit()
    conn.close()
    print("✔ Test complaint cleaned up. Database is verified and ready!\n")

if __name__ == "__main__":
    test_database()
