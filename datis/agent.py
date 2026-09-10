"""Single, unprivileged owner of the OpenVPN management Unix socket."""
import logging
import os
import select
import socket
import time
import uuid
from collections import deque
from .core import db, init_db, status, verify, allowed_attempt, charge, audit, state

log = logging.getLogger('datis.agent')

def notify(message):
    path = os.environ.get('NOTIFY_SOCKET')
    if path:
        if path.startswith('@'):
            path = '\0' + path[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(path)
            s.sendall(message.encode())

class Engine:
    def __init__(self, send):
        self.transport = send
        self.pending = deque()
        self.last_probe = time.monotonic()
        self.cid_session = {}
        self.epoch = uuid.uuid4().hex
        self.event = None
        self.env = {}
        self.ident = ()

    def send(self, command):
        self.pending.append((command.split()[0], time.monotonic()))
        self.transport(command)

    def sid(self, cid):
        return self.cid_session.get(int(cid), f'{self.epoch}:{int(cid)}')

    def start(self):
        with db() as c:
            c.execute('UPDATE vpn_sessions SET ended=? WHERE ended IS NULL', (int(time.time()),))
            state(c, 'agent_connected', 1)
        self.send('bytecount 2')
        self.send('hold release')

    def auth(self, event, cid, kid, env):
        user_name = env.get('username', '')
        password = env.get('password', '')
        result = False
        now = int(time.time())
        with db() as c:
            old = c.execute('SELECT * FROM vpn_sessions WHERE sid=? AND ended IS NULL', (self.sid(cid),)).fetchone()
            if event == 'CONNECT' and not old:
                self.cid_session[cid] = f'{self.epoch}:{cid}:{uuid.uuid4().hex}'
            user = c.execute('SELECT * FROM users WHERE username=?', (user_name,)).fetchone()
            # REAUTH may omit credentials; only a live, already approved CID can be reused.
            if event == 'REAUTH' and old:
                user = c.execute('SELECT * FROM users WHERE id=?', (old['user_id'],)).fetchone()
                identity_ok = not user_name or user_name == user['username']
                valid = identity_ok and (not password or verify(user['password_hash'], password))
            else:
                peer = env.get('untrusted_ip', env.get('untrusted_ip6', 'unknown'))
                # Limit both source and username to bound password-hashing work.
                permitted = allowed_attempt(c, 'vpn-ip:'+peer, 30) and allowed_attempt(c, 'vpn-user:'+user_name, 15)
                valid = permitted and user is not None and verify(user['password_hash'], password)
            if valid and status(user, now) == 'active' and not (old and old['kill_requested']):
                count = c.execute('SELECT count(*) FROM vpn_sessions WHERE user_id=? AND ended IS NULL AND sid<>?',
                                  (user['id'], self.sid(cid))).fetchone()[0]
                if count < user['max_connections']:
                    if not old:
                        c.execute('INSERT INTO vpn_sessions(sid,cid,user_id,started,address) VALUES(?,?,?,?,?)',
                                  (self.sid(cid), cid, user['id'], now, env.get('untrusted_ip',env.get('untrusted_ip6',''))))
                        audit(c, 'vpn', 'connect-approved', user['username'])
                    result = True
        if result:
            self.send(f'client-auth-nt {cid} {kid}')
        else:
            self.send(f'client-deny {cid} {kid} "Access denied"')
            if event == 'REAUTH':
                self.send(f'client-kill {cid}')

    def line(self, line):
        if line.startswith('>CLIENT:ENV,'):
            value = line[len('>CLIENT:ENV,'):]
            if value == 'END':
                self.finish()
            elif self.event and '=' in value:
                key, value = value.split('=', 1)
                if len(self.env) > 100:
                    raise ValueError('Too many environment fields')
                self.env[key] = value
        elif line.startswith('>CLIENT:'):
            parts = line[len('>CLIENT:'):].split(',')
            if parts[0] in ('CONNECT','REAUTH','ESTABLISHED','DISCONNECT'):
                self.event, self.ident, self.env = parts[0], tuple(int(x) for x in parts[1:]), {}
                if any(x < 0 for x in self.ident):
                    raise ValueError('Invalid client identifier')
            # ADDRESS includes an IP/subnet rather than all-integer fields.
            # Unknown event kinds are ignored for forward compatibility.
        elif line.startswith('>BYTECOUNT_CLI:'):
            cid, rx, tx = map(int, line.split(':',1)[1].split(','))
            with db() as c:
                known = charge(c, self.sid(cid), rx, tx)
            if not known:
                self.send(f"client-kill {cid}")
        elif line.startswith('>HOLD:'):
            self.send('hold release')
        elif line.startswith(('SUCCESS:', 'ERROR:')):
            command = self.pending.popleft()[0] if self.pending else None
            # A client can disappear between a scheduled kill and its execution.
            if line.startswith('ERROR:') and command != 'client-kill':
                raise RuntimeError('OpenVPN rejected a management command')

    def finish(self):
        event, ids, env = self.event, self.ident, self.env
        self.event, self.ident, self.env = None, (), {}
        if event in ('CONNECT', 'REAUTH'):
            self.auth(event, ids[0], ids[1], env)
        elif event == 'ESTABLISHED':
            with db() as c:
                c.execute('UPDATE vpn_sessions SET established=1 WHERE sid=?', (self.sid(ids[0]),))
        elif event == 'DISCONNECT':
            with db() as c:
                charge(c, self.sid(ids[0]), int(env.get('bytes_received', 0)), int(env.get('bytes_sent', 0)))
                c.execute('UPDATE vpn_sessions SET ended=? WHERE sid=?', (int(time.time()), self.sid(ids[0])))

    def tick(self):
        if self.pending and time.monotonic()-self.pending[0][1] > 10:
            raise TimeoutError("OpenVPN command acknowledgement timed out")
        if time.monotonic()-self.last_probe > 5:
            self.send("pid")
            self.last_probe = time.monotonic()
        now = int(time.time())
        kills = []
        with db() as c:
            state(c, 'agent_heartbeat', now)
            for s in c.execute('SELECT s.*,u.username,u.enabled,u.expires,u.quota,u.used FROM vpn_sessions s JOIN users u ON s.user_id=u.id WHERE s.ended IS NULL').fetchall():
                if status(s, now) != 'active' or s['kill_requested'] or (not s['established'] and now-s['started'] > 60):
                    kills.append(s['cid'])
        for cid in kills:
            self.send(f'client-kill {cid}')
        notify('WATCHDOG=1')

    def close(self):
        with db() as c:
            state(c, 'agent_connected', 0)
            c.execute('UPDATE vpn_sessions SET ended=? WHERE ended IS NULL', (int(time.time()),))

def run():
    init_db()
    notify('READY=1')
    while True:
        engine = None
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect(os.environ.get('DATIS_MANAGEMENT', '/run/datisvpn/management.sock'))
                def send(command):
                    sock.sendall((command+'\n').encode())
                engine = Engine(send)
                engine.start()
                buffer = b''
                last_tick = 0.0
                while True:
                    if select.select([sock], [], [], .5)[0]:
                        chunk = sock.recv(65536)
                        if not chunk:
                            raise ConnectionError('Management connection closed')
                        buffer += chunk
                        if len(buffer) > 262144:
                            raise ValueError('Oversized management frame')
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n',1)
                            engine.line(line.decode('utf-8', errors='strict').rstrip('\r'))
                    if time.monotonic()-last_tick >= 1:
                        engine.tick()
                        last_tick = time.monotonic()
        except (FileNotFoundError, ConnectionRefusedError, ConnectionError, TimeoutError):
            log.warning('Management unavailable; retrying')
        finally:
            if engine:
                engine.close()
        notify('WATCHDOG=1')
        time.sleep(2)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    run()
