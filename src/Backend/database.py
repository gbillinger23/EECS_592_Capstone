''' Prologue Comments 
Artifact: database.py
Description: Defines sqlite database class to store network packets.
Creation Date: 2/13/2026
Revision Dates:
    2026-03-25: Added check_same_thread=False so the same PacketDatabase instance
                can be used from Flask request threads AND the packet_worker thread
                without raising sqlite3.ProgrammingError.
                Also added a threading.Lock() around writes to prevent corruption.
Preconditions:
    No inputs.
Postconditions:
    No outputs. 
Errors/Exceptions: none
Side effects: none
Invariants: none
'''

import sqlite3
import threading
from datetime import datetime
import boto3, json

class PacketDatabase:
    def __init__(self, db_name="packets.db"):
        self.db_name = db_name
        self._lock   = threading.Lock()   # Serialise writes across threads
        self.conn    = None
        self.cursor  = None
        self.init_db()
        self.create_feedback_table()
        self.create_case_table()
        self.create_suppression_table()


    def init_db(self):
        """Initialize database and create table if it doesn't exist."""
        # check_same_thread=False lets Flask request threads reuse this connection
        self.conn   = sqlite3.connect(self.db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                src_ip    TEXT,
                dst_ip    TEXT,
                src_port  INTEGER,
                dst_port  INTEGER,
                protocol  TEXT
            )
        ''')
        self.conn.commit()

    def insert_metadata(self, metadata):
        """Insert packet metadata into database (thread-safe)."""
        with self._lock:
            self.cursor.execute('''
                INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                metadata['src_ip'],
                metadata['dst_ip'],
                metadata['src_port'],
                metadata['dst_port'],
                metadata['protocol']
            ))
            self.conn.commit()

    def create_case_table(self):
        with self._lock:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                attack_type TEXT,
                severity TEXT,
                status TEXT,
                packets TEXT,
                countermeasures TEXT,
                notes TEXT,
                timestamp TEXT
                )
            """)
            self.conn.commit()

    def create_feedback_table(self):
        with self._lock:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT,
                    feedback TEXT,
                    note TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    timestamp TEXT
                )
            """)
            self.conn.commit()

    def create_suppression_table(self):
        with self._lock:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS suppressions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT,
                    field TEXT,
                    value TEXT,
                    created TEXT
                )
            """)
            self.conn.commit()


    def get_all_packets(self):
        """Retrieve all packets from database (thread-safe)."""
        with self._lock:
            self.cursor.execute('SELECT * FROM packets')
            return self.cursor.fetchall()
        
    def get_all_feedback(self):
        with self._lock:
            cur = self.conn.execute("SELECT * FROM feedback ORDER BY id DESC")
            return cur.fetchall()

    def insert_case(self, title, attack_type, severity, status, packets, countermeasures, notes):
        with self._lock:
            self.cursor.execute("""
                INSERT INTO cases (title, attack_type, severity, status, packets, countermeasures, notes, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                title,
                attack_type,
                severity,
                status,
                packets,
                countermeasures,
                notes,
                datetime.utcnow().isoformat()
            ))
            self.conn.commit()

    def insert_feedback(self, rule_id, feedback, note, src_ip, dst_ip, timestamp):
        with self._lock:
            self.conn.execute("""
                INSERT INTO feedback (rule_id, feedback, note, src_ip, dst_ip, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (rule_id, feedback, note, src_ip, dst_ip, timestamp))
            self.conn.commit()

    def sync_suppressions_to_s3(self):
        print("[DEBUG] STARTING S3 CLIENT")
        s3 = boto3.client("s3")
        print("[DEBUG] GETTING SUPPRESSIONS")
        rows = self.get_suppressions()

        suppressions = [
            {"rule_id": r[1], "field": r[2], "value": r[3]}
            for r in rows
        ]

        print("[DEBUG] Syncing S3 Start")
        s3.put_object(
            Bucket="monitoring-pcap-storage",
            Key="suppressions/suppressions.json",
            Body=json.dumps(suppressions).encode("utf-8"),
            ContentType="application/json"
        )
        print("[DEBUG] Syncing S3 End")

    def insert_suppression(self, rule_id, field, value):
        with self._lock:
            self.cursor.execute("""
                INSERT INTO suppressions (rule_id, field, value, created)
                VALUES (?, ?, ?, datetime('now'))
            """, (rule_id, field, value))
            self.conn.commit()
        print("[DEBUG] ENTERING S3 SYNC FUNCTION")
        self.sync_suppressions_to_s3()
    
    def get_cases(self):
        with self._lock:
            self.cursor.execute("SELECT * FROM cases ORDER BY id DESC")
            rows = self.cursor.fetchall()

            # Convert tuple rows → dicts manually
            cases = []
            for r in rows:
                cases.append({
                    "id": r[0],
                    "title": r[1],
                    "attack_type": r[2],
                    "severity": r[3],
                    "status": r[4],
                    "packets": r[5],
                    "countermeasures": r[6],
                    "notes": r[7],
                    "timestamp": r[8]
                })
            return cases
        
    def get_case(self, case_id):
        with self._lock:
            self.cursor.execute("SELECT * FROM cases WHERE id=?", (case_id,))
            r = self.cursor.fetchone()
            if not r:
                return None
            return {
                "id": r[0],
                "title": r[1],
                "attack_type": r[2],
                "severity": r[3],
                "status": r[4],
                "packets": r[5],
                "countermeasures": r[6],
                "notes": r[7],
                "timestamp": r[8]
            }
        
    def get_suppressions(self):
        with self._lock:
            self.cursor.execute("SELECT id, rule_id, field, value FROM suppressions ORDER BY id DESC")
            return self.cursor.fetchall()

        
    def delete_suppression(self, sup_id):
        with self._lock:
            self.cursor.execute("DELETE FROM suppressions WHERE id=?", (sup_id,))
            self.conn.commit()

    def analyze_feedback_for_suppression(self):
        with self._lock:
            self.cursor.execute("""
                SELECT rule_id, src_ip, dst_ip, feedback
                FROM feedback
                WHERE feedback IN ('false_positive', 'benign')
            """)
            rows = self.cursor.fetchall()

        counts = {}

        for rule_id, src_ip, dst_ip, fb in rows:
            # Count by src_ip
            if src_ip:
                key = (rule_id, "src_ip", src_ip)
                counts[key] = counts.get(key, 0) + 1

            # Count by dst_ip
            if dst_ip:
                key = (rule_id, "dst_ip", dst_ip)
                counts[key] = counts.get(key, 0) + 1

        # Add suppressions for repeated patterns
        for (rule_id, field, value), count in counts.items():
            if count >= 5:
                print("[REFINEMENT] Creating suppression:", rule_id, field, value)
                self.insert_suppression(rule_id, field, value)

    def close(self):
        """Close database connection."""
        self.conn.close()