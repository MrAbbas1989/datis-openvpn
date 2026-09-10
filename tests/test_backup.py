import os
import sqlite3
import subprocess
import sys

def test_consistent_backup_without_secret_logging(database):
    output=database/'backup.sqlite'
    proc=subprocess.run([sys.executable,'-m','datis.cli','backup',str(output)],capture_output=True,text=True)
    assert proc.returncode==0,proc.stderr
    assert output.stat().st_mode & 0o777==0o600
    with sqlite3.connect(output) as c:
        assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        assert c.execute('SELECT username FROM users').fetchone()[0]=='abbas'
    again=subprocess.run([sys.executable,'-m','datis.cli','backup',str(output)],capture_output=True)
    assert again.returncode!=0
