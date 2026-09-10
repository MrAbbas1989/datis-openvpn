import functools
import hashlib
import io
import math
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from flask import Flask, abort, flash, redirect, render_template, request, send_file, session, url_for
from .core import db, init_db, NAME, password_hash, verify, status, audit, allowed_attempt

LABELS = {'active':'فعال','expired':'منقضی','limited':'اتمام حجم','disabled':'غیرفعال'}

def create_app(test_config=None):
    app = Flask(__name__)
    key = os.environ.get('DATIS_SECRET', '')
    if len(key) < 32 and not test_config:
        raise RuntimeError('DATIS_SECRET must contain at least 32 random characters')
    app.config.update(SECRET_KEY=key, SESSION_COOKIE_NAME='datis_session', SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE='Strict', SESSION_COOKIE_SECURE=os.environ.get('DATIS_SECURE_COOKIE','1')=='1',
                      PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=16384)
    if test_config:
        app.config.update(test_config)
    init_db()

    def token_hash(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def require_admin(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            token = session.get('token', '')
            with db() as c:
                row = c.execute('SELECT * FROM web_sessions WHERE token=? AND expires>?', (token_hash(token), int(time.time()))).fetchone()
            if not row:
                session.clear()
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return wrapped

    @app.before_request
    def csrf():
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(32)
        if request.method == 'POST':
            supplied = request.form.get('csrf', '')
            if not secrets.compare_digest(supplied, session['csrf']):
                abort(400, 'درخواست نامعتبر است؛ صفحه را تازه کنید.')

    @app.after_request
    def headers(resp):
        resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['Referrer-Policy'] = 'no-referrer'
        resp.headers['Cache-Control'] = 'no-store'
        if app.config['SESSION_COOKIE_SECURE']:
            resp.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return resp

    @app.template_filter('gb')
    def gb(value):
        return f'{value / 1_000_000_000:,.2f}'

    @app.template_filter('date')
    def date(value):
        return datetime.fromtimestamp(value, timezone.utc).strftime('%Y-%m-%d %H:%M') if value else '—'

    @app.context_processor
    def context():
        return dict(labels=LABELS)

    @app.route('/login', methods=['GET','POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username','')[:48]
            password = request.form.get('password','')
            ok = False
            with db() as c:
                # Behind Nginx all clients share a conservative global cap. No spoofable forwarded headers.
                allowed = allowed_attempt(c, 'web-ip:'+str(request.remote_addr), 30) and allowed_attempt(c, 'web-user:'+username, 10)
                admin = c.execute('SELECT * FROM admins WHERE username=?', (username,)).fetchone()
                if allowed and admin and verify(admin['password_hash'], password):
                    session.clear()
                    session['csrf'] = secrets.token_urlsafe(32)
                    token = secrets.token_urlsafe(32)
                    session['token'], session['username'] = token, username
                    session.permanent = True
                    c.execute('DELETE FROM web_sessions WHERE expires<?', (int(time.time()),))
                    c.execute('INSERT INTO web_sessions VALUES(?,?,?)', (token_hash(token), username, int(time.time())+28800))
                    audit(c, username, 'admin-login', '')
                    ok = True
            if ok:
                return redirect(url_for('dashboard'))
            flash('نام کاربری یا رمز نادرست است، یا تعداد تلاش‌ها بیش از حد مجاز است.', 'error')
        return render_template('login.html')

    @app.post('/logout')
    @require_admin
    def logout():
        with db() as c:
            c.execute('DELETE FROM web_sessions WHERE token=?', (token_hash(session['token']),))
        session.clear()
        return redirect(url_for('login'))

    @app.get('/')
    @require_admin
    def dashboard():
        q = request.args.get('q','')[:100]
        selected = request.args.get('status','')
        page = max(1, min(100000, request.args.get('page',1,type=int)))
        with db() as c:
            all_users = [dict(u) for u in c.execute('SELECT u.*,(SELECT count(*) FROM vpn_sessions s WHERE s.user_id=u.id AND s.ended IS NULL) AS online FROM users u ORDER BY u.id DESC')]
            health = dict(c.execute('SELECT key,value FROM state').fetchall())
            online = c.execute('SELECT s.*,u.username FROM vpn_sessions s JOIN users u ON s.user_id=u.id WHERE s.ended IS NULL ORDER BY s.started DESC LIMIT 100').fetchall()
        for u in all_users:
            u['status'] = status(u)
        filtered = [u for u in all_users if q.casefold() in (u['username']+' '+u['note']).casefold() and (not selected or u['status']==selected)]
        stats = dict(total=len(all_users), active=sum(u['status']=='active' for u in all_users), online=sum(u['online'] for u in all_users), used=sum(u['used'] for u in all_users))
        healthy = health.get('agent_connected')=='1' and int(time.time())-int(health.get('agent_heartbeat','0'))<10
        return render_template('dashboard.html', users=filtered[(page-1)*50:page*50], stats=stats, healthy=healthy,
                               online=online, q=q, selected=selected, page=page, pages=max(1,math.ceil(len(filtered)/50)))

    def fields():
        quota_gb = request.form.get('quota','')
        # Decimal input avoids float/NaN/overflow surprises in byte accounting.
        from decimal import Decimal, InvalidOperation
        try:
            quota = Decimal(quota_gb)
            if not quota.is_finite() or quota < 0 or quota > 1_000_000:
                raise ValueError()
            quota_bytes = int(quota*1_000_000_000)
            if quota != 0 and quota_bytes == 0:
                raise ValueError()
            expires = int(datetime.strptime(request.form.get('expires',''), '%Y-%m-%dT%H:%M').replace(tzinfo=timezone.utc).timestamp())
            limit = int(request.form.get('max_connections','1'))
            if not 1 <= limit <= 100 or expires < 0 or expires > 4102444800:
                raise ValueError()
        except (ValueError, InvalidOperation, OverflowError):
            raise ValueError('حجم، تاریخ یا تعداد اتصال معتبر نیست.')
        return quota_bytes, expires, limit, request.form.get('note','')[:500]

    @app.route('/users/new', methods=['GET','POST'])
    @require_admin
    def new_user():
        if request.method == 'POST':
            try:
                username = request.form.get('username','')
                if not NAME.fullmatch(username):
                    raise ValueError('نام کاربری: ۳ تا ۴۸ حرف انگلیسی، عدد، نقطه، خط تیره یا زیرخط.')
                hashed = password_hash(request.form.get('password',''))
                quota, expires, limit, note = fields()
                with db() as c:
                    c.execute('INSERT INTO users(username,password_hash,quota,expires,max_connections,note,created) VALUES(?,?,?,?,?,?,?)',
                              (username,hashed,quota,expires,limit,note,int(time.time())))
                    audit(c, session['username'], 'user-create', username)
                flash('کاربر ساخته شد. فایل اتصال را از فهرست کاربران دانلود کنید.', 'success')
                return redirect(url_for('dashboard'))
            except sqlite3.IntegrityError:
                flash('این نام کاربری قبلاً ساخته شده است.', 'error')
            except ValueError as e:
                flash(str(e), 'error')
        defaults = dict(username='', quota=50_000_000_000, expires=int(time.time())+30*86400,max_connections=1,note='')
        return render_template('user.html', user=defaults, new=True,
                               expiry=datetime.fromtimestamp(defaults['expires'],timezone.utc).strftime('%Y-%m-%dT%H:%M'))

    @app.route('/users/<int:uid>', methods=['GET','POST'])
    @require_admin
    def edit_user(uid):
        with db() as c:
            user = c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
        if not user:
            abort(404)
        if request.method == 'POST':
            try:
                quota, expires, limit, note = fields()
                password = request.form.get('password','')
                hashed = password_hash(password) if password else None
                with db() as c:
                    c.execute('UPDATE users SET quota=?,expires=?,max_connections=?,note=? WHERE id=?', (quota,expires,limit,note,uid))
                    if hashed:
                        c.execute('UPDATE users SET password_hash=? WHERE id=?',(hashed,uid))
                        c.execute('UPDATE vpn_sessions SET kill_requested=1 WHERE user_id=? AND ended IS NULL',(uid,))
                    # Enforce a lowered connection cap immediately by reconnecting all sessions.
                    if limit < user['max_connections']:
                        c.execute('UPDATE vpn_sessions SET kill_requested=1 WHERE user_id=? AND ended IS NULL',(uid,))
                    audit(c, session['username'], 'user-update', user['username'])
                flash('تغییرات ذخیره شد.', 'success')
                return redirect(url_for('dashboard'))
            except ValueError as e:
                flash(str(e),'error')
        return render_template('user.html', user=user, new=False,
                               expiry=datetime.fromtimestamp(user['expires'],timezone.utc).strftime('%Y-%m-%dT%H:%M'))

    @app.post('/users/<int:uid>/action')
    @require_admin
    def user_action(uid):
        action = request.form.get('action')
        if action not in ('toggle','disconnect','reset'):
            abort(400)
        with db() as c:
            u = c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
            if not u:
                abort(404)
            if action == 'toggle':
                c.execute('UPDATE users SET enabled=1-enabled WHERE id=?',(uid,))
            elif action == 'disconnect':
                c.execute('UPDATE vpn_sessions SET kill_requested=1 WHERE user_id=? AND ended IS NULL',(uid,))
            elif action == 'reset':
                # Counter baselines stay intact: the next sample only charges NEW bytes.
                c.execute('UPDATE users SET used=0 WHERE id=?',(uid,))
            audit(c,session['username'],'user-'+action,u['username'])
        flash('درخواست ثبت شد؛ قطع نشست به فعال بودن سرویس اکانتینگ نیاز دارد.', 'success')
        return redirect(url_for('dashboard'))

    @app.get('/users/<int:uid>/profile')
    @require_admin
    def profile(uid):
        with db() as c:
            u = c.execute('SELECT username FROM users WHERE id=?',(uid,)).fetchone()
            if not u:
                abort(404)
            audit(c,session['username'],'profile-download',u['username'])
        p = Path(os.environ.get('DATIS_PROFILE','/etc/datisvpn/client.ovpn'))
        if not p.is_file():
            abort(503, 'فایل اتصال هنوز توسط نصاب ساخته نشده است.')
        return send_file(io.BytesIO(p.read_bytes()),as_attachment=True,download_name=f"DatisVPN-{u['username']}.ovpn",mimetype='application/x-openvpn-profile')

    @app.get('/audit')
    @require_admin
    def audit_page():
        with db() as c:
            rows = c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 200').fetchall()
        return render_template('audit.html', rows=rows)

    @app.route('/password', methods=['GET','POST'])
    @require_admin
    def change_password():
        if request.method == 'POST':
            try:
                hashed = password_hash(request.form.get('password',''))
                with db() as c:
                    admin = c.execute('SELECT * FROM admins WHERE username=?',(session['username'],)).fetchone()
                    if not verify(admin['password_hash'],request.form.get('current','')):
                        raise ValueError('رمز فعلی نادرست است.')
                    c.execute('UPDATE admins SET password_hash=? WHERE username=?',(hashed,session['username']))
                    c.execute('DELETE FROM web_sessions WHERE username=?',(session['username'],))
                    audit(c,session['username'],'admin-password-change','')
                session.clear()
                return redirect(url_for('login'))
            except ValueError as e:
                flash(str(e),'error')
        return render_template('password.html')

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(503)
    def error(exc):
        return render_template('error.html', message=exc.description, code=exc.code), exc.code

    return app
