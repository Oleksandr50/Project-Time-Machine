"""Authenticated backup controls. Every mutation also passes the shared CSRF/role gate."""
from fastapi import APIRouter,Request,Form,HTTPException
from fastapi.responses import RedirectResponse
from . import auth,projects,jobs,backups,i18n
from .config import settings

router=APIRouter()


def back():
    return RedirectResponse('/backups?project_id='+str(settings.project_id),status_code=303)


def admin_transaction(request,password):
    return auth.admin_transaction(request.state.auth['digest'],password,auth.peer(request))


@router.get('/api/jobs')
def status(request:Request):
    # No actor-controlled identifiers or exception text in the projection.
    fields=('id','task','kind','state','created_at','started_at','finished_at','progress_bytes',
            'total_bytes','progress_files','total_files','error_code','result_point_id','attempts')
    rows=[]
    for row in jobs.polled_jobs(settings.project_id):
        result={key:row[key] for key in fields}
        result['state_label']=i18n.tr('engine.state.'+row['state'])
        rows.append(result)
    return {'jobs':rows}


@router.post('/actions/verify')
def verify(request:Request,point_id:str=Form(default='')):
    jobs.enqueue(settings.project_id,request.state.user['user_id'],task='verify',point_id=point_id or None)
    return back()


@router.post('/actions/cancel')
def cancel(request:Request,job_id:str=Form(...)):
    jobs.cancel(job_id,settings.project_id,request.state.user['user_id'])
    return back()


@router.post('/backups/policy')
def policy(request:Request,secret_policy:str=Form(...),key_id:str=Form(default=''),
           auto_delete:str=Form(default='off'),keep_last:int=Form(default=20),
           min_age_days:int=Form(default=30),current_password:str=Form(default='')):
    with admin_transaction(request,current_password) as (conn,user):
        backups.save_policy(settings.project_id,secret_policy,key_id,auto_delete=='on',keep_last,min_age_days,conn)
    return back()


@router.post('/backups/schedule')
def schedule(request:Request,task:str=Form(...),kind:str=Form(default='full'),
             interval:int=Form(default=86400),enabled:str=Form(default='off'),current_password:str=Form(default='')):
    with admin_transaction(request,current_password) as (conn,user):
        jobs.schedule(settings.project_id,user['user_id'],task,kind,interval,enabled=='on',conn)
    return back()


@router.post('/backups/protect')
def protect(request:Request,point_id:str=Form(...),protected:str=Form(default='off'),
            current_password:str=Form(default='')):
    with admin_transaction(request,current_password):
        backups.protect(point_id,protected=='on')
    return back()


@router.post('/backups/cleanup')
def cleanup(request:Request,confirm:str=Form(default=''),current_password:str=Form(default='')):
    with admin_transaction(request,current_password) as (conn,user):
        if confirm!='delete':raise HTTPException(400,'engine.confirm')
        jobs.enqueue(settings.project_id,user['user_id'],task='retention',conn=conn)
    return back()
