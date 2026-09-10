import argparse
import getpass
import os
import sqlite3
from pathlib import Path
from .core import init_db, db, db_path, NAME, password_hash, audit

def main():
    p = argparse.ArgumentParser(description='Datis OpenVPN administration')
    sub = p.add_subparsers(dest='command', required=True)
    a = sub.add_parser('admin', help='Create/reset an administrator; prompts for password')
    a.add_argument('username')
    b = sub.add_parser('backup', help='Consistent online SQLite backup (contains private data)')
    b.add_argument('destination')
    args = p.parse_args()
    init_db()
    if args.command == 'admin':
        if not NAME.fullmatch(args.username):
            p.error('Username must be 3–48 safe ASCII characters')
        password = getpass.getpass('New password (12+ characters): ')
        if password != getpass.getpass('Repeat password: '):
            p.error('Passwords do not match')
        hashed = password_hash(password)
        with db() as c:
            c.execute('INSERT INTO admins VALUES(?,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash',(args.username,hashed))
            c.execute('DELETE FROM web_sessions WHERE username=?',(args.username,))
            audit(c,'cli','admin-reset',args.username)
        print('Administrator saved; existing sessions revoked.')
    else:
        target = Path(args.destination).resolve()
        if target.exists() or str(target)==str(Path(db_path()).resolve()):
            p.error('Destination must not exist')
        fd = os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        os.close(fd)
        with sqlite3.connect(db_path()) as src, sqlite3.connect(target) as dest:
            src.backup(dest)
        print(f'Backup saved: {target}')

if __name__ == '__main__':
    main()
