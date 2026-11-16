"""Account UI. Identity always comes from the validated session, never form user_id."""
from datetime import datetime,timezone
from fastapi import APIRouter,Request,Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from . import auth,projects,i18n
from .ui import templates,safe_return
from .account_views import account_view

router=APIRouter()


def key(request):return request.state.auth['digest']


def language(request):
    return request.state.language


def render(request,name,**context):
    return templates.TemplateResponse(request=request,name=name,context={'request':request,'now':datetime.now(timezone.utc).isoformat(timespec='seconds'),**context})


@router.get('/setup')
def setup_page(request:Request):
    return render(request,'auth.html',setup=True,language=language(request),title_key='auth.setup')


@router.post('/setup')
def setup(request:Request,username:str=Form(default=''),password:str=Form(default=''),confirm_password:str=Form(default=''),language:str=Form(default='ru'),setup_code:str=Form(default='')):
    if password!=confirm_password:raise auth.AuthError(400,'Пароли не совпадают')
    request.state.new_session_raw=auth.bootstrap(key(request),username,password,auth.peer(request),language,setup_code,getattr(request.state,'remote_setup',False))
    request.state.language=language
    return RedirectResponse('/',status_code=303)


@router.get('/login')
def login_page(request:Request):
    return render(request,'auth.html',setup=False,language=language(request),title_key='auth.login')


@router.post('/login')
def login(request:Request,username:str=Form(default=''),password:str=Form(default=''),language:str=Form(default='ru')):
    request.state.new_session_raw=auth.login(key(request),username,password,auth.peer(request),language)
    request.state.language=language
    return RedirectResponse('/',status_code=303)


@router.post('/logout')
def logout(request:Request):
    auth.logout(key(request),auth.peer(request));request.state.clear_session=True
    return RedirectResponse('/login',status_code=303)


@router.get('/account')
def account(request:Request):
    return render(request,'account.html',title_key='nav.account',**account_view(request))


@router.post('/account/update')
def update_account(request:Request,username:str=Form(default=''),current_password:str=Form(default=''),new_password:str=Form(default=''),language:str=Form(default='ru')):
    changed=auth.profile(key(request),current_password,auth.peer(request),username,new_password,language)
    request.state.language=language
    request.state.user['language']=language
    if changed:request.state.clear_session=True
    return RedirectResponse('/login' if changed else '/account',status_code=303)


@router.post('/account/revoke')
def revoke_own(request:Request,session_id:int=Form(...)):
    auth.revoke(key(request),auth.peer(request),session_id)
    return RedirectResponse('/account',status_code=303)


@router.get('/admin/users')
def users(request:Request):
    return render(request,'users.html',title_key='nav.users',admin_projects=projects.list_projects(True),**account_view(request,admin=True))


@router.post('/admin/users/create')
def create_user(request:Request,username:str=Form(default=''),password:str=Form(default=''),role:str=Form(default='viewer'),current_password:str=Form(default='')):
    auth.create_user(key(request),current_password,auth.peer(request),username,password,role)
    return RedirectResponse('/admin/users',status_code=303)


@router.post('/admin/users/update')
def edit_user(request:Request,user_id:int=Form(...),username:str=Form(default=''),role:str=Form(default='viewer'),enabled:str=Form(default='off'),version:int=Form(...),current_password:str=Form(default='')):
    auth.edit_user(key(request),current_password,auth.peer(request),user_id,username,role,enabled=='on',version)
    return RedirectResponse('/admin/users',status_code=303)


@router.post('/admin/users/reset')
def reset(request:Request,user_id:int=Form(...),new_password:str=Form(default=''),current_password:str=Form(default='')):
    auth.reset_password(key(request),current_password,auth.peer(request),user_id,new_password)
    return RedirectResponse('/admin/users',status_code=303)


@router.post('/admin/access')
def access(request:Request,user_id:int=Form(...),project_id:int=Form(...),allowed:str=Form(default='off'),can_restore:str=Form(default='off'),current_password:str=Form(default='')):
    auth.grant(key(request),current_password,auth.peer(request),user_id,project_id,allowed=='on',can_restore=='on')
    return RedirectResponse('/admin/users',status_code=303)


@router.post('/admin/sessions/revoke')
def revoke(request:Request,session_id:int=Form(...),current_password:str=Form(default='')):
    auth.revoke(key(request),auth.peer(request),session_id,current_password=current_password)
    return RedirectResponse('/admin/users',status_code=303)


@router.post('/admin/network')
def network(request:Request,enabled:str=Form(default='off'),current_password:str=Form(default='')):
    auth.network(key(request),current_password,auth.peer(request),enabled=='on')
    return RedirectResponse('/admin/users',status_code=303)


@router.post('/account/preferences')
def preferences(request:Request,locale:str=Form(...),theme:str=Form(default='system'),scale:int=Form(default=100),return_to:str=Form(default='/')):
    target=safe_return(return_to)
    auth.preferences(key(request),auth.peer(request),locale,theme,scale)
    request.state.language=locale
    request.state.user.update(language=locale,theme=theme,scale=scale)
    return RedirectResponse(target,status_code=303)
