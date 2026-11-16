"""Server sessions and explicit authorization. Credentials never enter audit data."""
from contextlib import contextmanager
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
import time
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError, InvalidHashError
from . import projects
from .migrations import utcnow

COOKIE='ptm_session'
HASHER=PasswordHasher(time_cost=3,memory_cost=65536,parallelism=4,hash_len=32,salt_len=16,type=Type.ID)
HASH_LOCK=threading.BoundedSemaphore(2)
DUMMY_HASH=HASHER.hash(secrets.token_urlsafe(32))
from .i18n import LANGUAGES
LEGACY_LANGUAGES=('ru','en','pl','uk')


class AuthError(Exception):
    def __init__(self,status,detail): self.status=status;self.detail=detail


def digest(raw): return hashlib.sha256(raw.encode('ascii')).hexdigest()


def csrf(raw): return hmac.new(raw.encode('ascii'),b'ptm-csrf-v1',hashlib.sha256).hexdigest()


def loopback(peer):
    try:
        ip=ipaddress.ip_address(peer)
        if getattr(ip,'ipv4_mapped',None): ip=ip.ipv4_mapped
        return ip.is_loopback
    except ValueError: return False


def peer(request): return request.client.host if request.client else 'unknown'


def username(value):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,64}',value):
        raise AuthError(400,'Логин: 3–64 символа A–Z, a–z, 0–9, _, . или -')
    return value.lower()


def password_hash(value):
    if len(value)<12 or len(value.encode('utf-8'))>1024:
        raise AuthError(400,'Пароль: не менее 12 символов, не более 1024 байт')
    with HASH_LOCK:return HASHER.hash(value)


def verify(encoded,value):
    if len(value.encode('utf-8'))>1024:return False
    try:
        with HASH_LOCK:return HASHER.verify(encoded,value)
    except (VerificationError,InvalidHashError):return False


def event(conn,actor,action,peer_address,result='success',target=None,project=None,details=None):
    details=details or {}
    allowed={'old_role','new_role','old_enabled','new_enabled','allowed','can_restore'}
    if set(details)-allowed:raise ValueError('Unsupported audit fields')
    conn.execute('INSERT INTO user_audit(created_at,actor_id,event,target_id,project_id,peer,result,details) VALUES(?,?,?,?,?,?,?,?)',
                 (utcnow(),actor,action,target,project,peer_address,result,json.dumps(details,sort_keys=True)))


def state():
    with projects.registry() as c:
        row=c.execute('SELECT * FROM auth_settings WHERE id=1').fetchone()
        if row is None:
            from .migrations import MigrationError
            raise MigrationError('Missing auth state')
        result=dict(row)
        # A new LAN profile has network access enabled by default without rewriting
        # registry rows. An explicit Administrator decision always takes precedence.
        if projects.base_settings.lan_access and not result['network_enabled']:
            preference=c.execute("SELECT event FROM user_audit WHERE event IN ('network_enabled','network_disabled') AND result='success' ORDER BY id DESC LIMIT 1").fetchone()
            if preference is None:result['network_enabled']=1
        return result


def _lookup(conn,key,touch=False):
    row=conn.execute("SELECT s.id AS session_id,s.digest,s.user_id,s.user_version,s.created_at,s.last_seen,s.expires_at,s.revoked_at,u.username,u.role,COALESCE(p.locale,u.language) AS language,COALESCE(p.theme,'system') AS theme,COALESCE(p.scale,100) AS scale,u.enabled,u.auth_version FROM sessions s LEFT JOIN users u ON u.id=s.user_id LEFT JOIN user_preferences p ON p.user_id=u.id WHERE s.digest=?",(key,)).fetchone()
    if not row:return None
    row=dict(row);now=time.time();cfg=projects.base_settings
    if row['revoked_at'] is not None or row['expires_at']<=now or now-row['last_seen']>=cfg.session_idle_seconds:
        return None
    if row['user_id'] is not None and (not row['enabled'] or row['auth_version']!=row['user_version']):return None
    if touch:conn.execute('UPDATE sessions SET last_seen=? WHERE id=?',(now,row['session_id']))
    return row


def session(raw):
    if not isinstance(raw,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',raw):return None
    with projects.registry() as c:return _lookup(c,digest(raw),touch=True)


def _new_session(conn,user,peer_address):
    raw=secrets.token_urlsafe(32);now=time.time()
    conn.execute('INSERT INTO sessions(digest,user_id,user_version,created_at,last_seen,expires_at,peer) VALUES(?,?,?,?,?,?,?)',
                 (digest(raw),user['id'] if user else None,user['auth_version'] if user else None,
                  now,now,now+(projects.base_settings.session_absolute_seconds if user else 600),peer_address))
    conn.execute('DELETE FROM sessions WHERE user_id IS NULL AND expires_at<?',(now-86400,))
    return raw


def anonymous(peer_address):
    _reserve([('preauth:'+peer_address,projects.base_settings.login_attempt_limit*10)])
    with projects.registry() as c:return _new_session(c,None,peer_address)


def bootstrap(key,login,password,peer_address,language='ru',setup_code='',require_setup_code=False):
    if require_setup_code or not loopback(peer_address):
        from . import setup_codes
        _reserve([('setup:'+peer_address,projects.base_settings.login_attempt_limit),('setup-global',projects.base_settings.login_attempt_limit*10)])
        if not projects.base_settings.remote_setup or not setup_codes.valid(projects.base_settings,setup_code):raise AuthError(403,'auth.setup_code_invalid')
    login=username(login);encoded=password_hash(password)
    if language not in LANGUAGES:raise AuthError(400,'Неизвестный язык')
    with projects.registry() as c:
        c.execute('BEGIN IMMEDIATE')
        actor=_lookup(c,key)
        if not actor:raise AuthError(403,'Сессия мастера истекла')
        if c.execute('SELECT setup_completed FROM auth_settings').fetchone()[0] or c.execute('SELECT 1 FROM users').fetchone():
            raise AuthError(409,'Первоначальная настройка уже завершена')
        now=utcnow()
        uid=c.execute('INSERT INTO users(username,password_hash,role,language,created_at,updated_at) VALUES(?,?,?,?,?,?)',
                      (login,encoded,'administrator',language if language in LEGACY_LANGUAGES else 'en',now,now)).lastrowid
        c.execute('INSERT INTO user_preferences(user_id,locale) VALUES(?,?)',(uid,language))
        c.execute('UPDATE auth_settings SET setup_completed=1 WHERE id=1')
        c.execute('UPDATE sessions SET revoked_at=? WHERE user_id IS NULL',(time.time(),))
        user=c.execute('SELECT id,auth_version FROM users WHERE id=?',(uid,)).fetchone()
        raw=_new_session(c,user,peer_address)
        event(c,uid,'setup_completed',peer_address)
    from . import setup_codes
    try:setup_codes.consume(projects.base_settings)
    except OSError:pass  # Setup is already committed; a leftover code can never create another admin.
    return raw


def _reserve(scopes):
    cfg=projects.base_settings;now=time.time()
    with projects.registry() as c:
        c.execute('BEGIN IMMEDIATE')
        for scope,limit in scopes:
            key=hashlib.sha256(scope.encode('utf-8')).hexdigest()
            row=c.execute('SELECT * FROM login_limits WHERE scope=?',(key,)).fetchone()
            if row and now-row['window_start']<cfg.login_window_seconds and row['attempts']>=limit:
                raise AuthError(429,'Слишком много попыток. Повторите позже.')
        for scope,limit in scopes:
            key=hashlib.sha256(scope.encode('utf-8')).hexdigest()
            row=c.execute('SELECT window_start FROM login_limits WHERE scope=?',(key,)).fetchone()
            if not row or now-row[0]>=cfg.login_window_seconds:
                c.execute('INSERT OR REPLACE INTO login_limits VALUES(?,?,1)',(key,now))
            else:c.execute('UPDATE login_limits SET attempts=attempts+1 WHERE scope=?',(key,))
        c.execute('DELETE FROM login_limits WHERE window_start<?',(now-cfg.login_window_seconds*2,))


def login(key,login_name,password,peer_address,language='ru'):
    if language not in LANGUAGES:raise AuthError(400,'Неизвестный язык')
    normalized=login_name.lower()[:64]
    limit=projects.base_settings.login_attempt_limit
    _reserve([('ip:'+peer_address,limit*2),('login:'+normalized,limit),('global-login',limit*20)])
    with projects.registry() as c:
        row=c.execute('SELECT * FROM users WHERE username=?',(normalized,)).fetchone() if re.fullmatch(r'[A-Za-z0-9_.-]{3,64}',login_name) else None
    good=verify(row['password_hash'] if row else DUMMY_HASH,password)
    with projects.registry() as c:
        c.execute('BEGIN IMMEDIATE')
        current=_lookup(c,key)
        fresh=c.execute('SELECT * FROM users WHERE id=?',(row['id'],)).fetchone() if row else None
        if not good or not fresh or not fresh['enabled'] or fresh['auth_version']!=row['auth_version']:
            event(c,None,'login_failed',peer_address,'denied',row['id'] if row else None)
            c.commit()
            raise AuthError(401,'Неверный логин или пароль')
        if not current:raise AuthError(403,'Сессия входа истекла')
        c.execute('UPDATE users SET language=? WHERE id=?',(language if language in LEGACY_LANGUAGES else 'en',row['id']))
        c.execute('INSERT INTO user_preferences(user_id,locale) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET locale=excluded.locale',(row['id'],language))
        c.execute('UPDATE sessions SET revoked_at=? WHERE id=?',(time.time(),current['session_id']))
        raw=_new_session(c,fresh,peer_address)
        event(c,row['id'],'login_success',peer_address)
        return raw


def actor(conn,key,admin=False):
    user=_lookup(conn,key)
    if not user or user['user_id'] is None:raise AuthError(401,'Требуется вход')
    if admin and user['role']!='administrator':raise AuthError(403,'Требуется роль Administrator')
    return user


def _reauth(key,password,peer_address,admin=False):
    with projects.registry() as c:
        user=actor(c,key,admin)
        row=c.execute('SELECT password_hash FROM users WHERE id=?',(user['user_id'],)).fetchone()
    _reserve([('reauth:'+str(user['user_id']),projects.base_settings.login_attempt_limit*2)])
    if not verify(row['password_hash'],password):
        with projects.registry() as c:event(c,user['user_id'],'reauth_failed',peer_address,'denied')
        raise AuthError(403,'Текущий пароль неверен')
    return user


@contextmanager
def admin_transaction(key,password,peer_address):
    prior=_reauth(key,password,peer_address,admin=True)
    with projects.registry() as c:
        c.execute('BEGIN IMMEDIATE');user=actor(c,key,admin=True)
        if user['auth_version']!=prior['auth_version']:raise AuthError(409,'Учётная запись изменилась. Войдите снова.')
        yield c,user


def visible_ids(user):
    if user['role']=='administrator':return None
    with projects.registry() as c:
        return [r[0] for r in c.execute('SELECT project_id FROM project_access WHERE user_id=?',(user['user_id'],))]


def can_restore(user,project_id):
    if not user:return False
    with projects.registry() as c:
        try:current=actor(c,user.get('digest',''))
        except AuthError:return False
        if current['role']=='administrator':return True
        if current['role']!='operator':return False
        return bool(c.execute('SELECT 1 FROM project_access WHERE user_id=? AND project_id=? AND can_restore=1',(current['user_id'],project_id)).fetchone())


def logout(key,peer_address):
    with projects.registry() as c:
        user=actor(c,key)
        c.execute('UPDATE sessions SET revoked_at=? WHERE id=?',(time.time(),user['session_id']))
        event(c,user['user_id'],'logout',peer_address)


def create_user(key,current_password,peer_address,login_name,password,role):
    login_name=username(login_name)
    if role not in ('administrator','operator','viewer'):raise AuthError(400,'Неизвестная роль')
    encoded=password_hash(password)
    with admin_transaction(key,current_password,peer_address) as (c,user):
        if c.execute('SELECT 1 FROM users WHERE username=?',(login_name,)).fetchone():raise AuthError(409,'Логин уже занят')
        now=utcnow()
        uid=c.execute('INSERT INTO users(username,password_hash,role,created_at,updated_at) VALUES(?,?,?,?,?)',
                      (login_name,encoded,role,now,now)).lastrowid
        event(c,user['user_id'],'user_created',peer_address,target=uid,details={'new_role':role})
        return uid


def edit_user(key,password,peer_address,uid,login_name,role,enabled,version):
    login_name=username(login_name)
    if role not in ('administrator','operator','viewer'):raise AuthError(400,'Неизвестная роль')
    with admin_transaction(key,password,peer_address) as (c,user):
        target=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
        if not target:raise AuthError(404,'Пользователь не найден')
        if target['auth_version']!=version:raise AuthError(409,'Данные изменились: обновите страницу')
        if target['role']=='administrator' and target['enabled'] and (role!='administrator' or not enabled):
            if c.execute("SELECT count(*) FROM users WHERE role='administrator' AND enabled=1").fetchone()[0]<=1:
                raise AuthError(409,'Нельзя отключить или понизить последнего администратора')
        if c.execute('SELECT 1 FROM users WHERE username=? AND id!=?',(login_name,uid)).fetchone():raise AuthError(409,'Логин уже занят')
        c.execute('UPDATE users SET username=?,role=?,enabled=?,auth_version=auth_version+1,updated_at=? WHERE id=?',
                  (login_name,role,int(enabled),utcnow(),uid))
        c.execute('UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL',(time.time(),uid))
        event(c,user['user_id'],'user_updated',peer_address,target=uid,details={'old_role':target['role'],'new_role':role,'old_enabled':bool(target['enabled']),'new_enabled':bool(enabled)})


def reset_password(key,password,peer_address,uid,new_password):
    encoded=password_hash(new_password)
    with admin_transaction(key,password,peer_address) as (c,user):
        if not c.execute('SELECT 1 FROM users WHERE id=?',(uid,)).fetchone():raise AuthError(404,'Пользователь не найден')
        c.execute('UPDATE users SET password_hash=?,auth_version=auth_version+1,updated_at=? WHERE id=?',(encoded,utcnow(),uid))
        c.execute('UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL',(time.time(),uid))
        event(c,user['user_id'],'password_reset',peer_address,target=uid)


def grant(key,password,peer_address,uid,pid,allowed,restore):
    with admin_transaction(key,password,peer_address) as (c,user):
        target=c.execute('SELECT role FROM users WHERE id=?',(uid,)).fetchone()
        if not target or not c.execute('SELECT 1 FROM projects WHERE id=?',(pid,)).fetchone():raise AuthError(404,'Пользователь или проект не найден')
        if restore and target['role']!='operator':raise AuthError(400,'Отдельное разрешение восстановления предназначено для Operator')
        if restore and not allowed:raise AuthError(400,'Сначала разрешите доступ к проекту')
        if allowed:c.execute('INSERT INTO project_access VALUES(?,?,?) ON CONFLICT(user_id,project_id) DO UPDATE SET can_restore=excluded.can_restore',(uid,pid,int(restore)))
        else:c.execute('DELETE FROM project_access WHERE user_id=? AND project_id=?',(uid,pid))
        # ACL changes immediately invalidate every session of the affected user.
        c.execute('UPDATE users SET auth_version=auth_version+1,updated_at=? WHERE id=?',(utcnow(),uid))
        c.execute('UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL',(time.time(),uid))
        event(c,user['user_id'],'project_access_changed',peer_address,target=uid,project=pid,details={'allowed':bool(allowed),'can_restore':bool(restore)})


def profile(key,current_password,peer_address,login_name,new_password,language):
    login_name=username(login_name)
    if language not in LANGUAGES:raise AuthError(400,'Неизвестный язык')
    prior=_reauth(key,current_password,peer_address)
    encoded=password_hash(new_password) if new_password else None
    with projects.registry() as c:
        c.execute('BEGIN IMMEDIATE');user=actor(c,key)
        if user['auth_version']!=prior['auth_version']:raise AuthError(409,'Данные изменились')
        if c.execute('SELECT 1 FROM users WHERE username=? AND id!=?',(login_name,user['user_id'])).fetchone():raise AuthError(409,'Логин уже занят')
        changed=encoded is not None or login_name!=user['username']
        c.execute('UPDATE users SET username=?,language=?,updated_at=? WHERE id=?',(login_name,language if language in LEGACY_LANGUAGES else 'en',utcnow(),user['user_id']))
        c.execute('INSERT INTO user_preferences(user_id,locale) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET locale=excluded.locale',(user['user_id'],language))
        if changed:
            if encoded:c.execute('UPDATE users SET password_hash=? WHERE id=?',(encoded,user['user_id']))
            c.execute('UPDATE users SET auth_version=auth_version+1 WHERE id=?',(user['user_id'],))
            c.execute('UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL',(time.time(),user['user_id']))
        event(c,user['user_id'],'profile_changed',peer_address)
        return changed


def revoke(key,peer_address,sid,current_password=None):
    if current_password is not None:
        with admin_transaction(key,current_password,peer_address) as (c,user):_revoke(c,user,sid,peer_address,True)
    else:
        with projects.registry() as c:
            c.execute('BEGIN IMMEDIATE');user=actor(c,key);_revoke(c,user,sid,peer_address,False)


def _revoke(c,user,sid,peer_address,admin):
    target=c.execute('SELECT user_id FROM sessions WHERE id=?',(sid,)).fetchone()
    if not target or (not admin and target['user_id']!=user['user_id']):raise AuthError(404,'Сессия не найдена')
    c.execute('UPDATE sessions SET revoked_at=? WHERE id=?',(time.time(),sid))
    event(c,user['user_id'],'session_revoked',peer_address,target=target['user_id'])


def network(key,password,peer_address,enabled):
    with admin_transaction(key,password,peer_address) as (c,user):
        c.execute('UPDATE auth_settings SET network_enabled=? WHERE id=1',(int(enabled),))
        if not enabled:
            for row in c.execute('SELECT id,peer FROM sessions WHERE revoked_at IS NULL').fetchall():
                if not loopback(row['peer']):c.execute('UPDATE sessions SET revoked_at=? WHERE id=?',(time.time(),row['id']))
        event(c,user['user_id'],'network_enabled' if enabled else 'network_disabled',peer_address)


def account_data(user,admin=False):
    with projects.registry() as c:
        users=[dict(r) for r in c.execute('SELECT id,username,role,enabled,auth_version,language,created_at,updated_at FROM users ORDER BY id')] if admin else []
        sessions=[dict(r) for r in c.execute('SELECT s.id,u.username,s.user_id,s.created_at,s.last_seen,s.expires_at,s.revoked_at FROM sessions s JOIN users u ON u.id=s.user_id '+('' if admin else 'WHERE s.user_id=? ')+'ORDER BY s.id DESC LIMIT 200',() if admin else (user['user_id'],))]
        history=[dict(r) for r in c.execute('SELECT a.created_at,u.username,a.event,a.result,a.target_id,a.project_id,a.peer,a.details FROM user_audit a LEFT JOIN users u ON u.id=a.actor_id '+('' if admin else 'WHERE (a.actor_id=? OR a.target_id=?) ')+'ORDER BY a.id DESC LIMIT 200',() if admin else (user['user_id'],user['user_id']))]
        grants=[dict(r) for r in c.execute('SELECT * FROM project_access')] if admin else []
    now=time.time()
    for item in sessions:
        item['active']=(item['revoked_at'] is None and item['expires_at']>now and
                        now-item['last_seen']<projects.base_settings.session_idle_seconds)
    return dict(users=users,sessions=sessions,history=history,grants=grants)


def preferences(key,peer_address,locale,theme,scale):
    if locale not in LANGUAGES or theme not in ('system','dark','light') or scale not in range(80,141,10):
        raise AuthError(400,'error.validation')
    with projects.registry() as c:
        c.execute('BEGIN IMMEDIATE');user=actor(c,key)
        c.execute('INSERT INTO user_preferences VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET locale=excluded.locale,theme=excluded.theme,scale=excluded.scale',
                  (user['user_id'],locale,theme,scale))
        if locale in LEGACY_LANGUAGES:c.execute('UPDATE users SET language=? WHERE id=?',(locale,user['user_id']))
        event(c,user['user_id'],'preferences_changed',peer_address)
