import psycopg2

try:
    conn = psycopg2.connect(
        host="10.0.0.110",
        port=5432,
        user="vulnstrike",
        password="vulnstrike",
        dbname="vulnstrike",
        connect_timeout=5
    )

    print("Connected to PostgreSQL")

    cur = conn.cursor()
    cur.execute("SELECT version();")
    print(cur.fetchone())

    conn.close()

except Exception as e:
    print("Connection failed:", e)