import sqlite3

conn = sqlite3.connect("nmids.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scans(
id INTEGER PRIMARY KEY,
target TEXT,
port INTEGER,
service TEXT
)
""")

conn.commit()

def save_scan(target, results):

    for port, service in results:

        cursor.execute(
            """
            INSERT INTO scans
            (target, port, service)
            VALUES (?, ?, ?)
            """,
            (target, port, service)
        )

    conn.commit()