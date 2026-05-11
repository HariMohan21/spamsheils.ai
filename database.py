import sqlite3


def create_database():
    conn = sqlite3.connect("spamshield.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT,
        result TEXT,
        risk_score INTEGER,
        warnings_found INTEGER,
        preview TEXT
    )
    """)

    conn.commit()
    conn.close()


def save_scan(scan_time, result, risk_score, warnings_found, preview):
    conn = sqlite3.connect("spamshield.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO scan_history
    (scan_time, result, risk_score, warnings_found, preview)
    VALUES (?, ?, ?, ?, ?)
    """, (
        scan_time,
        result,
        risk_score,
        warnings_found,
        preview
    ))

    conn.commit()
    conn.close()


def get_scan_history():
    conn = sqlite3.connect("spamshield.db")

    query = """
    SELECT
        scan_time,
        result,
        risk_score,
        warnings_found,
        preview
    FROM scan_history
    ORDER BY id DESC
    """

    history = conn.execute(query).fetchall()
    conn.close()

    return history