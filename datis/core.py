import contextlib
import os
import re
import sqlite3
import time
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{2,47}\Z')
SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 quota INTEGER NOT NULL CHECK(quota>=0), used INTEGER NOT NULL DEFAULT 0 CHECK(used>=0),
 expires INTEGER NOT NULL, max_connections INTEGER NOT NULL CHECK(max_connections BETWEEN 1 AND 100),
 enabled INTEGER NOT NULL DEFAULT 1, note TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS vpn_sessions (
 sid TEXT PRIMARY KEY, cid INTEGER NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id),
 started INTEGER NOT NULL, ended INTEGER, rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0,
 address TEXT NOT NULL DEFAULT '', established INTEGER NOT NULL DEFAULT 0, kill_requested INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS active_users ON vpn_sessions(user_id,ended);
CREATE TABLE IF NOT EXISTS admins (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS web_sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS attempts (scope TEXT PRIMARY KEY, count INTEGER NOT NULL, started INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
PRAGMA user_version=1;
'''

def db_path():
    return os.environ.get('DATIS_DB', '/var/lib/datisvpn/panel.db')

@contextlib.contextmanager
def db():
    conn = sqlite3.connect(db_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA busy_timeout=10000')
    try:
        conn.execute('BEGIN IMMEDIATE')
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    Path(db_path()).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path()) as c:
        version = c.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0, 1):
            raise RuntimeError('Unsupported database schema')
        c.execute('PRAGMA journal_mode=WAL')
        c.executescript(SCHEMA)
    os.chmod(db_path(), 0o600)

def password_hash(password):
    if not 12 <= len(password) <= 128 or any(ord(ch) < 32 or ord(ch) == 127 for ch in password):
        raise ValueError('رمز باید بین ۱۲ تا ۱۲۸ کاراکتر باشد.')
    return generate_password_hash(password, method='scrypt:32768:8:1')

def verify(stored, password):
    return isinstance(password, str) and len(password) <= 128 and check_password_hash(stored, password)

def status(user, now=None):
    now = int(time.time()) if now is None else now
    if not user['enabled']:
        return 'disabled'
    if user['expires'] <= now:
        return 'expired'
    if user['quota'] and user['used'] >= user['quota']:
        return 'limited'
    return 'active'

def audit(c, actor, action, target):
    c.execute('INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)',
              (int(time.time()), actor, action, str(target)))

def allowed_attempt(c, scope, limit=10, window=300):
    now = int(time.time())
    c.execute('DELETE FROM attempts WHERE started<?', (now-window,))
    row = c.execute('SELECT * FROM attempts WHERE scope=?', (scope,)).fetchone()
    if row and row['count'] >= limit:
        return False
    c.execute('INSERT INTO attempts VALUES(?,1,?) ON CONFLICT(scope) DO UPDATE SET count=count+1', (scope, now))
    return True

def charge(c, sid, rx, tx):
    """Cumulative counters: persist only positive deltas; never reset at reauth."""
    if rx < 0 or tx < 0 or rx > 2**62 or tx > 2**62:
        raise ValueError('Invalid counters')
    s = c.execute('SELECT * FROM vpn_sessions WHERE sid=?', (sid,)).fetchone()
    if not s:
        return False
    rx, tx = max(rx, s['rx']), max(tx, s['tx'])
    delta = rx - s['rx'] + tx - s['tx']
    c.execute('UPDATE users SET used=used+? WHERE id=?', (delta, s['user_id']))
    c.execute('UPDATE vpn_sessions SET rx=?,tx=? WHERE sid=?', (rx, tx, sid))
    return True

def state(c, key, value):
    c.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, str(value)))
