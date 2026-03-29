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

class PacketDatabase:
    def __init__(self, db_name="packets.db"):
        self.db_name = db_name
        self._lock   = threading.Lock()   # Serialise writes across threads
        self.conn    = None
        self.cursor  = None
        self.init_db()

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

    def get_all_packets(self):
        """Retrieve all packets from database (thread-safe)."""
        with self._lock:
            self.cursor.execute('SELECT * FROM packets')
            return self.cursor.fetchall()

    def close(self):
        """Close database connection."""
        self.conn.close()