#!/usr/bin/env python3
"""Apply database schema migrations against $DATABASE_URL.

Mutates a database. Not obviously production from the command line, but the
contents show an irreversible ALTER/DROP, so a human should confirm.
"""
import os
import psycopg2

conn = psycopg2.connect(os.environ["DATABASE_URL"])
cur = conn.cursor()
cur.execute("ALTER TABLE users DROP COLUMN legacy_token;")
cur.execute("ALTER TABLE orders ADD COLUMN region TEXT NOT NULL DEFAULT 'eu';")
conn.commit()
print("migrations applied")
