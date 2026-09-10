import time
import pytest
from datis.agent import Engine
from datis.core import db, status
from conftest import PASSWORD

@pytest.fixture
def engine(database):
    commands = []
    e = Engine(commands.append)
    e.start()
    e.commands = commands
    return e

def event(e, typ='CONNECT', cid=0, kid=0, **env):
    e.line(f'>CLIENT:{typ},{cid}'+(f',{kid}' if typ in ('CONNECT','REAUTH') else ''))
    for k,v in env.items():
        e.line(f'>CLIENT:ENV,{k}={v}')
    e.line('>CLIENT:ENV,END')

def connect(e,cid=0,**kwargs):
    event(e,cid=cid,username='abbas',password=PASSWORD,untrusted_ip='203.0.113.9',**kwargs)

def used():
    with db() as c:
        return c.execute('SELECT used FROM users').fetchone()[0]

def test_cumulative_duplicate_out_of_order_and_final_accounting(engine):
    connect(engine)
    engine.line('>BYTECOUNT_CLI:0,100,200')
    engine.line('>BYTECOUNT_CLI:0,100,200')
    engine.line('>BYTECOUNT_CLI:0,90,180')
    assert used()==300
    event(engine,'DISCONNECT',bytes_received=120,bytes_sent=250)
    event(engine,'DISCONNECT',bytes_received=120,bytes_sent=250)
    assert used()==370

def test_quota_kills_and_rejects_reconnect(engine):
    connect(engine)
    engine.line('>BYTECOUNT_CLI:0,600,500')
    engine.tick()
    assert 'client-kill 0' in engine.commands
    event(engine,'DISCONNECT',bytes_received=600,bytes_sent=500)
    connect(engine,1)
    assert engine.commands[-1].startswith('client-deny 1')

def test_expiry_and_disabled(engine):
    connect(engine)
    with db() as c:
        c.execute('UPDATE users SET expires=?',(int(time.time())-1,))
    engine.tick()
    assert engine.commands[-1]=='client-kill 0'
    event(engine,'REAUTH',username='abbas',password=PASSWORD)
    assert any(cmd.startswith('client-deny 0') for cmd in engine.commands)
    with db() as c:
        c.execute('UPDATE users SET expires=?,enabled=0',(int(time.time())+86400,))
    connect(engine,1)
    assert engine.commands[-1].startswith('client-deny 1')

def test_concurrent_connection_limit_counts_pending(engine):
    connect(engine,0)
    connect(engine,1)
    assert 'client-auth-nt 0 0' in engine.commands
    assert engine.commands[-1].startswith('client-deny 1')

def test_reauth_does_not_reset_or_double_count(engine):
    connect(engine)
    engine.line('>BYTECOUNT_CLI:0,100,200')
    event(engine,'REAUTH')
    assert engine.commands[-1]=='client-auth-nt 0 0'
    engine.line('>BYTECOUNT_CLI:0,150,250')
    assert used()==400

def test_reauth_cannot_switch_identity(engine):
    connect(engine)
    event(engine,'REAUTH',username='intruder')
    assert engine.commands[-2].startswith('client-deny')

def test_reset_while_connected_preserves_baseline(engine):
    connect(engine)
    engine.line('>BYTECOUNT_CLI:0,100,200')
    with db() as c:
        c.execute('UPDATE users SET used=0')
    engine.line('>BYTECOUNT_CLI:0,130,240')
    assert used()==70

def test_cid_reuse_gets_new_session(engine):
    connect(engine)
    first=engine.sid(0)
    event(engine,'DISCONNECT',bytes_received=100,bytes_sent=200)
    connect(engine)
    assert engine.sid(0)!=first
    engine.line('>BYTECOUNT_CLI:0,50,60')
    assert used()==410

def test_agent_restart_preserves_usage_and_closes_stale_sessions(engine):
    connect(engine)
    engine.line('>BYTECOUNT_CLI:0,100,200')
    fresh=Engine(lambda command:None)
    fresh.start()
    assert used()==300
    with db() as c:
        assert c.execute('SELECT count(*) FROM vpn_sessions WHERE ended IS NULL').fetchone()[0]==0
    connect(fresh)
    fresh.line('>BYTECOUNT_CLI:0,10,20')
    assert used()==330

def test_address_message_does_not_crash(engine):
    engine.line('>CLIENT:ADDRESS,0,10.87.0.2,1')
    engine.line('>CLIENT:ADDRESS,0,fd42:d47:15::1000,1')
    connect(engine)
    assert engine.commands[-1]=='client-auth-nt 0 0'

def test_unknown_users_wrong_password_and_injection(engine):
    event(engine,username='missing',password=PASSWORD)
    assert engine.commands[-1].startswith('client-deny')
    event(engine,cid=1,username='abbas',password='wrong')
    assert engine.commands[-1].startswith('client-deny')
    event(engine,cid=2,username='abbas; kill all',password=PASSWORD)
    assert engine.commands[-1].startswith('client-deny')
    assert all('abbas' not in cmd for cmd in engine.commands)

def test_kill_race_error_is_nonfatal(engine):
    engine.pending.clear()
    engine.send('client-kill 123')
    engine.line('ERROR: client-kill command failed')
    engine.send('bytecount 2')
    with pytest.raises(RuntimeError):
        engine.line('ERROR: command failed')

def test_boundary_status():
    assert status(dict(enabled=1,quota=100,used=100,expires=200),100)=='limited'
    assert status(dict(enabled=1,quota=0,used=100,expires=100),100)=='expired'
    assert status(dict(enabled=1,quota=0,used=100,expires=200),100)=='active'

def test_short_session_final_bytes_only(engine):
    connect(engine)
    event(engine,'DISCONNECT',bytes_received=75,bytes_sent=25)
    assert used()==100

def test_multiple_sessions_share_one_quota(engine):
    with db() as c:
        c.execute('UPDATE users SET max_connections=2')
    connect(engine,0)
    connect(engine,1)
    engine.line('>BYTECOUNT_CLI:0,250,250')
    engine.line('>BYTECOUNT_CLI:1,250,250')
    engine.tick()
    assert 'client-kill 0' in engine.commands and 'client-kill 1' in engine.commands

def test_pending_timeout(engine):
    connect(engine)
    with db() as c:
        c.execute('UPDATE vpn_sessions SET started=?',(int(time.time())-61,))
    engine.tick()
    assert engine.commands[-1]=='client-kill 0'
