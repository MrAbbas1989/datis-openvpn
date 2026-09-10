import time
import pytest
from datis.core import init_db, db, password_hash
from datis.web import create_app

PASSWORD = 'Correct-test-password-123'

@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.setenv('DATIS_DB', str(tmp_path/'panel.db'))
    init_db()
    with db() as c:
        c.execute('INSERT INTO users(username,password_hash,quota,expires,max_connections,created) VALUES(?,?,?,?,?,?)',
                  ('abbas',password_hash(PASSWORD),1000,int(time.time())+86400,1,int(time.time())))
        c.execute('INSERT INTO admins VALUES(?,?)',('admin',password_hash(PASSWORD)))
    return tmp_path

@pytest.fixture
def app(database):
    return create_app({'TESTING':True,'SECRET_KEY':'test-secret-not-for-production-123456','SESSION_COOKIE_SECURE':False})

@pytest.fixture
def client(app):
    return app.test_client()

def csrf(client):
    client.get('/login')
    with client.session_transaction() as s:
        return s['csrf']

def login(client):
    response = client.post('/login',data={'csrf':csrf(client),'username':'admin','password':PASSWORD})
    assert response.status_code == 302
    with client.session_transaction() as s:
        return s['csrf']
