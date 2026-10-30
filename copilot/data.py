"""Synthetic, clearly fake customer data.

In production these tables would live in Snowflake (see
snowflake_schema.sql). Locally they live in SQLite so the demo runs
anywhere with only Python 3, no account and no API key. The SQL the
agent uses is deliberately plain SELECTs with a customer filter, so
the same queries map directly onto Snowflake secure views.
"""
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "customer.db"

CUSTOMERS = [
    ("CUST-1001", "Priya Sharma", "priya.sharma@example.com", "+1-555-010-1001", "Premium"),
    ("CUST-1002", "Arjun Patel", "arjun.patel@example.com", "+1-555-010-1002", "Standard"),
    ("CUST-1003", "Maya Chen", "maya.chen@example.com", "+1-555-010-1003", "Standard"),
]

ACCOUNTS = [
    # customer_id, account_id, account_type, masked display, full number (synthetic), status, balance, opened
    ("CUST-1001", "ACC-2001", "Savings", "****4321", "000011114321", "Active", 12450.75, "2021-03-15"),
    ("CUST-1002", "ACC-2002", "Checking", "****9876", "000022229876", "Active", 3420.10, "2019-07-22"),
    ("CUST-1003", "ACC-2003", "Savings", "****5550", "000033335550", "Active", 8930.40, "2022-11-08"),
]

ACTIVITY = [
    ("CUST-1001", "2026-10-21", "Salary credit", 5200.00, "Credit"),
    ("CUST-1001", "2026-10-19", "Online purchase", -84.20, "Debit"),
    ("CUST-1001", "2026-10-15", "Utility payment", -132.50, "Debit"),
    ("CUST-1002", "2026-10-20", "Salary credit", 4100.00, "Credit"),
    ("CUST-1002", "2026-10-18", "ATM withdrawal", -200.00, "Debit"),
    ("CUST-1003", "2026-10-21", "Interest credit", 18.75, "Credit"),
    ("CUST-1003", "2026-10-17", "Online purchase", -56.99, "Debit"),
]

TICKETS = [
    ("TKT-5001", "CUST-1001", "Card delivery delay", "In Progress",
     "2026-10-20", "Card dispatched on 2026-10-22. Expected delivery by 2026-10-27."),
    ("TKT-5002", "CUST-1001", "Address update request", "Completed",
     "2026-10-14", "Address updated and confirmed on 2026-10-18."),
    ("TKT-5003", "CUST-1002", "Billing question", "Waiting for customer",
     "2026-10-19", "We asked for the statement month to check. No reply yet."),
    ("TKT-5004", "CUST-1003", "Mobile app login help", "Resolved",
     "2026-10-16", "Password reset completed. Customer confirmed login works."),
]


def init_db(db_path=DB_PATH):
    """Rebuild the synthetic database from scratch (idempotent)."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript("""
        DROP TABLE IF EXISTS customers;
        DROP TABLE IF EXISTS accounts;
        DROP TABLE IF EXISTS activity;
        DROP TABLE IF EXISTS tickets;
        CREATE TABLE customers (customer_id TEXT PRIMARY KEY, name TEXT, email TEXT, phone TEXT, segment TEXT);
        CREATE TABLE accounts (customer_id TEXT, account_id TEXT PRIMARY KEY, account_type TEXT,
            display_number TEXT, full_number TEXT, status TEXT, balance REAL, opened_date TEXT);
        CREATE TABLE activity (customer_id TEXT, activity_date TEXT, description TEXT, amount REAL, direction TEXT);
        CREATE TABLE tickets (ticket_id TEXT PRIMARY KEY, customer_id TEXT, subject TEXT, status TEXT,
            opened_date TEXT, next_step TEXT);
        CREATE TABLE IF NOT EXISTS security_audit_log (
            audit_id TEXT PRIMARY KEY,
            timestamp TEXT,
            customer_id TEXT,
            prompt_hash TEXT,
            masked_prompt TEXT,
            is_safe INTEGER,
            risk_level TEXT,
            injection_score REAL,
            attack_vectors TEXT,
            pii_detected TEXT,
            toxicity_score REAL,
            action_taken TEXT,
            details TEXT,
            latency_ms REAL
        );
    """)
    cur.executemany("INSERT INTO customers VALUES (?,?,?,?,?)", CUSTOMERS)
    cur.executemany("INSERT INTO accounts VALUES (?,?,?,?,?,?,?,?)", ACCOUNTS)
    cur.executemany("INSERT INTO activity VALUES (?,?,?,?,?)", ACTIVITY)
    cur.executemany("INSERT INTO tickets VALUES (?,?,?,?,?,?)", TICKETS)
    conn.commit()
    conn.close()
    return db_path


def get_customer(db_path, customer_id):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM customers WHERE customer_id = ?", (customer_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_account(db_path, customer_id):
    """Structured lookup, always scoped to one customer. Never cross-customer."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM accounts WHERE customer_id = ?", (customer_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def list_accounts(db_path, customer_id):
    """List all accounts owned by a customer."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM accounts WHERE customer_id = ?", (customer_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_activity(db_path, customer_id, limit=3):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM activity WHERE customer_id = ? ORDER BY activity_date DESC LIMIT ?",
        (customer_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_ticket(db_path, customer_id, ticket_id=None):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    if ticket_id:
        # Ticket lookup is still scoped to this customer: a ticket id from
        # another customer must not be returned.
        row = conn.execute(
            "SELECT * FROM tickets WHERE ticket_id = ? AND customer_id = ?",
            (ticket_id, customer_id),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM tickets WHERE customer_id = ? ORDER BY opened_date DESC LIMIT 1",
            (customer_id,),
        ).fetchone()
    conn.close()
    return dict(row) if row else None


def list_tickets(db_path, customer_id):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM tickets WHERE customer_id = ? ORDER BY opened_date DESC",
        (customer_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
