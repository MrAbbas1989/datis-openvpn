import time
import sqlite3
from datis.core import db, verify
from conftest import login, csrf, PASSWORD

def test_protected_routes(client):
    for route in ('/','/audit','/users/new','/users/1','/users/1/profile','/password'):
        assert client.get(route).status_code==302

def test_csrf_required_even_at_login(client):
    assert client.post('/login',data={'username':'admin','password':PASSWORD}).status_code==400

def test_login_logout_and_server_session_revocation(client):
    token=login(client)
    assert client.get('/').status_code==200
    with db() as c:
        c.execute('DELETE FROM web_sessions')
    assert client.get('/').status_code==302
    token=login(client)
    assert client.post('/logout',data={'csrf':token}).status_code==302
    assert client.get('/').status_code==302

def fields(token,**changes):
    data=dict(csrf=token,username='newuser',password='New-test-password-456',quota='50',expires='2030-01-01T12:00',max_connections='2',note='test')
    return dict(data,**changes)

def test_create_edit_and_no_plaintext_password(client):
    token=login(client)
    assert client.post('/users/new',data=fields(token)).status_code==302
    with db() as c:
        u=c.execute('SELECT * FROM users WHERE username="newuser"').fetchone()
        uid=u['id']
        assert u['quota']==50_000_000_000
        assert u['password_hash']!='New-test-password-456'
        assert verify(u['password_hash'],'New-test-password-456')
    assert client.post(f'/users/{uid}',data=fields(token,quota='75',password='')).status_code==302
    with db() as c:
        assert c.execute('SELECT quota FROM users WHERE id=?',(uid,)).fetchone()[0]==75_000_000_000

def test_invalid_values_and_duplicate_name(client):
    token=login(client)
    for changes in ({'quota':'NaN'},{'quota':'Infinity'},{'quota':'-1'},{'max_connections':'0'},{'username':'../../etc/passwd'},{'username':'abbas'},{'expires':'bad'}):
        assert client.post('/users/new',data=fields(token,**changes)).status_code==200
    with db() as c:
        assert c.execute('SELECT count(*) FROM users').fetchone()[0]==1

def test_stored_xss_is_escaped(client):
    token=login(client)
    client.post('/users/new',data=fields(token,note='<script>alert(1)</script>'))
    data=client.get('/').data
    assert b'<script>alert(1)</script>' not in data
    assert b'&lt;script&gt;' in data

def test_mutations_reject_get_and_bad_csrf(client):
    token=login(client)
    assert client.get('/users/1/action').status_code==405
    assert client.post('/users/1/action',data={'action':'reset','csrf':'bad'}).status_code==400
    assert client.post('/users/1/action',data={'action':'arbitrary','csrf':token}).status_code==400

def test_action_and_audit(client):
    token=login(client)
    client.post('/users/1/action',data={'csrf':token,'action':'toggle'})
    with db() as c:
        assert c.execute('SELECT enabled FROM users').fetchone()[0]==0
        assert c.execute('SELECT action FROM audit ORDER BY id DESC LIMIT 1').fetchone()[0]=='user-toggle'

def test_rate_limit(client):
    token=csrf(client)
    for _ in range(10):
        client.post('/login',data={'csrf':token,'username':'admin','password':'wrong'})
    assert client.post('/login',data={'csrf':token,'username':'admin','password':PASSWORD}).status_code==200

def test_profile_requires_auth_and_contains_no_password(client,database,monkeypatch):
    p=database/'client.ovpn'
    p.write_text('client\nauth-user-pass\n')
    monkeypatch.setenv('DATIS_PROFILE',str(p))
    login(client)
    r=client.get('/users/1/profile')
    assert r.status_code==200 and b'auth-user-pass' in r.data
    assert PASSWORD.encode() not in r.data
    assert 'attachment' in r.headers['Content-Disposition']

def test_password_change_invalidates_all_sessions(client):
    token=login(client)
    assert client.post('/password',data={'csrf':token,'current':PASSWORD,'password':'Changed-password-123'}).status_code==302
    with db() as c:
        assert c.execute('SELECT count(*) FROM web_sessions').fetchone()[0]==0

def test_headers_and_large_body(client):
    r=client.get('/login')
    assert "frame-ancestors 'none'" in r.headers['Content-Security-Policy']
    assert 'HttpOnly' in r.headers['Set-Cookie'] and 'SameSite=Strict' in r.headers['Set-Cookie']
    assert client.post('/login',data={'password':'a'*20000}).status_code==413

def test_render_every_screen(client):
    login(client)
    for route in ('/','/audit','/users/new','/users/1','/password','/not-found'):
        response=client.get(route)
        assert response.status_code==(404 if route=='/not-found' else 200)
        assert 'lang="fa" dir="rtl"' in response.text
