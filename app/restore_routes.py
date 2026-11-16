"""Restore wizard: safe GETs, CSRF-protected preview and one-time confirmation."""
from fastapi import APIRouter,Request,Form,HTTPException
from fastapi.responses import RedirectResponse
from . import restores,auth,db,services,projects
from .config import settings
from .ui import render
from .tables import memory_page,column as C

router=APIRouter()
CHANGE_COLS=[C('path','common.path','path'),C('change','common.type','change'),C('type','common.type','restore_entry'),C('size','common.size','bytes')]


def preview_page(request,preview):
    spec=preview['spec'];table=memory_page(request,spec['plan']['changes'],CHANGE_COLS,default='path')
    counts={kind:sum(e['change']==kind for e in spec['plan']['changes']) for kind in ('added','modified','deleted')}
    return render(request,'restore_preview.html',title_key='restore.preview_title',preview=preview,table=table,counts=counts)


@router.get('/restore')
def page(request:Request):
    points=[];snapshots=[];legacy=[];operations=[]
    allowed=False
    if request.state.project:
        services.ensure_db()
        with db.db_conn() as conn:
            points=[dict(r) for r in conn.execute("SELECT p.*,b.created_at FROM backup_points p JOIN backups b ON b.id=p.backup_id WHERE p.state='available' ORDER BY b.id DESC")]
            snapshots=[dict(r) for r in conn.execute("SELECT id,created_at,description FROM snapshots WHERE content_status='recoverable' ORDER BY id DESC")]
            legacy=[dict(r) for r in conn.execute('SELECT b.* FROM backups b LEFT JOIN backup_points p ON p.backup_id=b.id WHERE p.id IS NULL ORDER BY b.id DESC')]
        operations=restores.operations()
        allowed=auth.can_restore(request.state.user,settings.project_id)
    try:
        selected=int(request.query_params.get('history_page','1'))
        if not 1<=selected<=1000000:raise ValueError
    except ValueError:raise HTTPException(400,'error.table')
    pages=max(1,(len(operations)+24)//25);selected=min(selected,pages)
    history=dict(total=len(operations),page=selected,pages=pages)
    return render(request,'restore.html',title_key='nav.restore',points=points,snapshots=snapshots,legacy=legacy,
                  operations=operations[(selected-1)*25:selected*25],history=history,can_restore=allowed)


@router.post('/restore/preview')
def preview(request:Request,source_type:str=Form(default=''),source_id:str=Form(default=''),source:str=Form(default=''),
            mode:str=Form(default='full'),destination:str=Form(default=''),paths:str=Form(default='')):
    if source and ':' in source:source_type,source_id=source.split(':',1)
    shown=restores.preview(request.state.user,request.state.session_raw,source_type,source_id,mode,destination,
                           [p.strip() for p in paths.splitlines() if p.strip()])
    return RedirectResponse('/restore/preview?project_id='+str(settings.project_id)+'&preview_id='+shown['id'],status_code=303)


@router.get('/restore/preview')
def show_preview(request:Request,preview_id:str):
    return preview_page(request,restores.get_preview(request.state.user,request.state.session_raw,preview_id))


@router.post('/restore/confirm')
def confirm(request:Request,preview_id:str=Form(...),confirmation_token:str=Form(...),
            acknowledge:str=Form(default='off'),confirmation:str=Form(default='')):
    restores.confirm(request.state.user,request.state.session_raw,preview_id,confirmation_token,acknowledge,confirmation)
    return RedirectResponse('/restore?project_id='+str(settings.project_id),status_code=303)


@router.post('/restore/recovery-preview')
def recovery(request:Request,operation_id:str=Form(...),method:str=Form(default='undo')):
    shown=restores.recovery_preview(request.state.user,request.state.session_raw,operation_id,method)
    return RedirectResponse('/restore/preview?project_id='+str(settings.project_id)+'&preview_id='+shown['id'],status_code=303)
