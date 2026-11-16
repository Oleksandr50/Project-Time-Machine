"""Deny-by-default HTTP gate, before any project context/history is opened."""
from fastapi.responses import PlainTextResponse, RedirectResponse
from . import auth,projects,security,i18n
from .responses import error_response
from .migrations import MigrationError
import sqlite3

PUBLIC={'/login','/setup'}
GLOBAL_READ={'/account','/admin/users','/settings'}
GLOBAL_WRITE={'/account/preferences','/logout','/account/update','/account/revoke','/admin/users/create','/admin/users/update',
              '/admin/users/reset','/admin/access','/admin/sessions/revoke','/admin/network'}
PROJECT_READ={'/projects','/restore','/compare/text','/','/timeline','/snapshots','/compare','/files','/file','/functions','/audit','/logs',
              '/logs/view','/sqlite','/backups','/backups/download','/report','/api/status','/api/jobs'}
PROJECT_WRITE={'/actions/analyze','/actions/backup','/actions/verify','/actions/cancel','/audit/review'}
PROJECT_ADMIN={'/projects/add','/projects/edit','/projects/remove','/backups/policy','/backups/schedule','/backups/protect','/backups/cleanup'}
PROJECT_RESTORE={'/restore/preview','/restore/confirm','/restore/recovery-preview'}
PROJECT_READ.update(('/restore/preview','/audit/export'))
PROXY_HEADERS={'forwarded','x-forwarded-for','x-forwarded-host','x-forwarded-proto','x-real-ip'}


def known(path,method):
    if path.startswith('/static/'):return method in ('GET','HEAD')
    if path in PUBLIC:return method in ('GET','POST')
    return (method=='GET' and path in GLOBAL_READ|PROJECT_READ) or (method=='POST' and path in GLOBAL_WRITE|PROJECT_RESTORE|PROJECT_WRITE|PROJECT_ADMIN)


def bootstrap_local(request):
    return (auth.loopback(auth.peer(request)) and
            (request.url.hostname=='localhost' or auth.loopback(request.url.hostname or '')) and
            not any(name in request.headers for name in PROXY_HEADERS))


async def fields(request):
    if getattr(request.state,'form',None) is not None:return request.state.form
    chunks=[];size=0
    async for chunk in request.stream():
        size+=len(chunk)
        if size>65536:raise auth.AuthError(413,'Форма слишком велика')
        chunks.append(chunk)
    # Starlette BaseHTTPMiddleware replays this bounded body to downstream Form handlers.
    request._body=b''.join(chunks)
    form=await request.form(max_files=0,max_fields=40,max_part_size=16384)
    request.state.form=form
    return form


def finish(request,response):
    raw=getattr(request.state,'new_session_raw',None) or getattr(request.state,'session_raw',None)
    if getattr(request.state,'clear_session',False):
        for name in (auth.COOKIE,security.CSRF_COOKIE,'ptm_active_project'):response.delete_cookie(name,path='/')
    elif raw:
        if getattr(request.state,'new_session_raw',None):
            response.set_cookie(auth.COOKIE,raw,httponly=True,samesite='strict',secure=request.url.scheme=='https',path='/')
        response.set_cookie(security.CSRF_COOKIE,auth.csrf(raw),httponly=True,samesite='strict',secure=request.url.scheme=='https',path='/')
    locale=getattr(request.state,'language','ru')
    if locale in i18n.CATALOGS:response.set_cookie('ptm_language',locale,httponly=True,samesite='strict',secure=request.url.scheme=='https')
    prefs=getattr(request.state,'user',None) or {}
    if prefs.get('theme') in ('system','dark','light'):response.set_cookie('ptm_theme',prefs['theme'],httponly=True,samesite='strict',secure=request.url.scheme=='https')
    response.headers['Content-Language']=locale
    response.headers['Cache-Control']='no-store'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Content-Security-Policy']="frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='same-origin'
    return response


async def gate(request,call_next):
    request.state.project=None;request.state.projects=[];request.state.all_projects=[]
    request.state.user=None;request.state.auth=None;request.state.csrf_token='';request.state.form=None
    request.state.language=i18n.detect(request)
    locale_token=i18n.current_locale.set(request.state.language)
    token=None
    request.state.operation=None
    try:
        if not security.management_client_allowed(request) or not security.management_host_allowed(request):
            raise auth.AuthError(403,'Адрес клиента или сервера не разрешён')
        if request.url.path=='/healthz' and request.method=='GET':
            if not bootstrap_local(request):raise auth.AuthError(403,'Адрес клиента или сервера не разрешён')
            from fastapi.responses import JSONResponse
            return finish(request,JSONResponse({'status':'ok', 'instance':__import__('os').environ.get('PTM_MANAGED_ID','standalone')}))
        state=auth.state()
        local=bootstrap_local(request)
        request.state.remote_setup=not local
        if not state['setup_completed']:
            if not local and not security.remote_setup_allowed(request):raise auth.AuthError(403,'Первоначальная настройка доступна только напрямую с localhost')
            if request.url.path not in PUBLIC and not request.url.path.startswith('/static/'):
                if request.method=='GET':return finish(request,RedirectResponse('/setup',status_code=303))
                raise auth.AuthError(403,'Сначала завершите первоначальную настройку')
        remote=not auth.loopback(auth.peer(request)) or any(name in request.headers for name in PROXY_HEADERS)
        if state['setup_completed'] and remote:
            if not state['network_enabled']:raise auth.AuthError(403,'Сетевой доступ выключен администратором')
            if projects.base_settings.require_https_remote and request.url.scheme!='https' and not security.direct_lan_http_allowed(request):
                raise auth.AuthError(403,'Для сетевого доступа требуется HTTPS')
        path=request.url.path
        if not known(path,request.method):raise auth.AuthError(404,'Маршрут не найден')
        if path.startswith('/static/'):return finish(request,await call_next(request))
        raw=request.cookies.get(auth.COOKIE,'');principal=auth.session(raw)
        if path in PUBLIC:
            if path=='/setup' and state['setup_completed']:raise auth.AuthError(410,'Первоначальная настройка уже завершена')
            if path=='/login' and not state['setup_completed']:return finish(request,RedirectResponse('/setup',status_code=303))
            if request.method=='GET' and not principal:
                raw=auth.anonymous(auth.peer(request));principal=auth.session(raw);request.state.new_session_raw=raw
        elif not principal or principal['user_id'] is None:
            if request.method=='GET' and not path.startswith('/api/'):
                return finish(request,RedirectResponse('/login',status_code=303))
            raise auth.AuthError(401,'Требуется вход')
        if not principal:raise auth.AuthError(403,'Сессия отсутствует или истекла. Обновите страницу.')
        request.state.auth=principal;request.state.session_raw=raw
        request.state.csrf_token=auth.csrf(raw)
        if principal['user_id'] is not None:
            request.state.user=principal
            if path not in PUBLIC:request.state.language=principal['language'] if principal['language'] in i18n.CATALOGS else 'en'
            i18n.current_locale.set(request.state.language)
        if request.method=='POST':
            if not security.same_origin(request):raise auth.AuthError(403,'Запрос с другого сайта запрещён')
            form=await fields(request)
            if path in PUBLIC and form.get('language') in i18n.CATALOGS:
                request.state.language=form['language'];i18n.current_locale.set(request.state.language)
            submitted=request.headers.get('x-csrf-token') or form.get('csrf_token','')
            if not security.valid_csrf(request.state.csrf_token,submitted):raise auth.AuthError(403,'Защитный токен отсутствует или устарел')
        if path in PUBLIC:return finish(request,await call_next(request))
        user=request.state.user
        if (path.startswith('/admin/') or path in PROJECT_ADMIN) and user['role']!='administrator':
            raise auth.AuthError(403,'Требуется роль Administrator')
        if path in PROJECT_WRITE and user['role'] not in ('administrator','operator'):
            raise auth.AuthError(403,'Viewer может только просматривать проекты')
        if path in GLOBAL_READ|GLOBAL_WRITE:
            ids=auth.visible_ids(user)
            request.state.projects=projects.list_projects(project_ids=ids)
            request.state.all_projects=projects.list_projects(True,project_ids=ids)
            chosen=request.cookies.get('ptm_active_project')
            request.state.project=next((p for p in request.state.projects if str(p['id'])==chosen),request.state.projects[0] if request.state.projects else None)
            return finish(request,await call_next(request))
        ids=auth.visible_ids(user)
        available=projects.list_projects(project_ids=ids)
        all_projects=projects.list_projects(include_disabled=True,project_ids=ids)
        value=request.query_params.get('project_id') or request.cookies.get('ptm_active_project')
        project=None
        if value:
            try:pid=int(value)
            except ValueError:pid=-1
            project=next((p for p in available if p['id']==pid),None)
            if not project and 'project_id' in request.query_params:raise auth.AuthError(404,'Проект недоступен')
        if project is None and available:project=available[0]
        request.state.projects=available;request.state.all_projects=all_projects;request.state.project=project
        if not project and path not in ('/','/projects/add','/projects','/restore'):raise auth.AuthError(404,'Проект недоступен')
        if path in PROJECT_RESTORE and request.method=='POST' and not auth.can_restore(user,project['id']):
            raise auth.AuthError(403,'engine.restore_access')
        token=projects.current_settings.set(projects.project_settings(project) if project else projects.base_settings)
        operation=None
        if request.method=='POST' or path in ('/backups/download','/audit/export'):
            target=project['id'] if project else None
            if path in PROJECT_ADMIN and path.startswith('/projects/'):
                try:target=int(request.state.form.get('project_id'))
                except (TypeError,ValueError):target=None
            operation=(path.strip('/').replace('/','_'),target)
            request.state.operation=operation
            with projects.registry() as c:
                auth.event(c,user['user_id'],operation[0]+'_started',auth.peer(request),'started',project=target)
        response=await call_next(request)
        if request.method=='POST' or path in ('/backups/download','/audit/export'):
            target=project['id'] if project else None
            if path in PROJECT_ADMIN and path.startswith('/projects/'):
                try:target=int(request.state.form.get('project_id'))
                except (TypeError,ValueError):target=None
            with projects.registry() as c:
                auth.event(c,user['user_id'],path.strip('/').replace('/','_'),auth.peer(request),
                           ('authorized' if path in ('/backups/download','/audit/export') else 'success') if response.status_code<400 else 'failed',project=target)
        if project and path!='/projects/remove':
            response.set_cookie('ptm_active_project',str(project['id']),httponly=True,samesite='strict',secure=request.url.scheme=='https')
        return finish(request,response)
    except auth.AuthError as exc:
        if request.state.user:
            with projects.registry() as c:auth.event(c,request.state.user['user_id'],'access_denied',auth.peer(request),'denied')
        response=error_response(request,exc.status,exc.detail)
        if exc.status==429:response.headers['Retry-After']=str(projects.base_settings.login_window_seconds)
        return finish(request,response)
    except (MigrationError,sqlite3.DatabaseError):
        record_failure(request)
        return finish(request,error_response(request,503,'error.storage'))
    except (OSError,ValueError) as exc:
        record_failure(request)
        detail=str(exc) if str(exc) in i18n.CATALOGS['ru'] or str(exc) in i18n.REVERSE else 'error.files'
        return finish(request,error_response(request,400,detail))
    except Exception as exc:
        import logging,secrets
        reference=secrets.token_hex(8)
        record_failure(request)
        logging.getLogger('ptm').error('PTM_INTERNAL_ERROR %s %s',reference,type(exc).__name__)
        return finish(request,error_response(request,500,'PTM_INTERNAL_ERROR: '+reference))
    finally:
        if token is not None:projects.current_settings.reset(token)
        i18n.current_locale.reset(locale_token)


def record_failure(request):
    operation=getattr(request.state,'operation',None)
    if not operation:return
    try:
        with projects.registry() as c:
            auth.event(c,request.state.user['user_id'],operation[0]+'_failed',auth.peer(request),'failed',project=operation[1])
    except (MigrationError,sqlite3.DatabaseError,OSError):
        # A durable 'started' already exists; never claim a completed operation.
        pass
