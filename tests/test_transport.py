"""Exercise the actual daemon over a fragmented Unix management stream."""
import os
import socket
import subprocess
import sys
import time
import pytest
from datis.core import db
from conftest import PASSWORD

@pytest.mark.skipif(os.environ.get("DATIS_SKIP_SOCKET_TEST")=="1", reason="Execution environment denies AF_UNIX sockets; run on Linux VPS or CI")
def test_daemon_protocol_over_unix_socket(database,monkeypatch):
    path=str(database/'management.sock')
    monkeypatch.setenv('DATIS_MANAGEMENT',path)
    server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)
    server.settimeout(10)
    proc=subprocess.Popen([sys.executable,'-m','datis.agent'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=os.environ.copy())
    conn=None
    try:
        conn,_=server.accept()
        conn.settimeout(10)
        stream=conn.makefile('rb')
        assert stream.readline()==b'bytecount 2\n'
        assert stream.readline()==b'hold release\n'
        conn.sendall(b'SUCCESS: bytecount enabled\nSUCCESS: hold released\n')
        frame=f'>CLIENT:CONNECT,8,0\n>CLIENT:ENV,username=abbas\n>CLIENT:ENV,password={PASSWORD}\n>CLIENT:ENV,untrusted_ip=203.0.113.4\n>CLIENT:ENV,END\n'.encode()
        conn.sendall(frame[:13]); conn.sendall(frame[13:])
        assert stream.readline()==b'client-auth-nt 8 0\n'
        conn.sendall(b'SUCCESS: authenticated\n>CLIENT:ESTABLISHED,8\n>CLIENT:ENV,END\n>CLIENT:ADDRESS,8,10.87.0.2,1\n>BYTECOUNT_CLI:8,600,500\n')
        command=stream.readline()
        if command==b'pid\n':
            conn.sendall(b'SUCCESS: pid=1234\n')
            command=stream.readline()
        assert command==b'client-kill 8\n'
        conn.sendall(b'SUCCESS: killed\n>CLIENT:DISCONNECT,8\n>CLIENT:ENV,bytes_received=650\n>CLIENT:ENV,bytes_sent=550\n>CLIENT:ENV,END\n')
        deadline=time.monotonic()+5
        result=None
        while time.monotonic()<deadline:
            with db() as c:
                result=c.execute('SELECT used FROM users').fetchone()[0]
            if result==1200:
                break
            time.sleep(.05)
        assert result==1200
        proc.terminate()
        proc.wait(timeout=5)
        # Agent process death closes its management connection. OpenVPN's
        # management-signal directive must separately be accepted on a real VPS.
        while conn.recv(4096):
            pass
    finally:
        if proc.poll() is None:
            proc.kill(); proc.wait(timeout=5)
        if conn:
            conn.close()
        server.close()
        stdout,stderr=proc.communicate()
        assert PASSWORD.encode() not in stdout+stderr
