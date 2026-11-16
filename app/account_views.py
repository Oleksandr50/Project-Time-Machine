from . import projects,auth
from .tables import column as C,sql_page
import time


def account_view(request,admin=False):
    section=request.query_params.get('section','users' if admin else 'sessions')
    if section not in (('users','sessions','history','network') if admin else ('sessions','history')):section='users' if admin else 'sessions'
    user=request.state.user
    with projects.registry() as conn:
        if section=='users':
            columns=[C('id','common.id'),C('username','auth.username'),C('role','auth.role','role'),C('enabled','common.status','enabled'),C('created_at','common.created','date')]
            table=sql_page(conn,request,'(SELECT id,username,role,enabled,auth_version,created_at FROM users)',columns,default='id',search=('username',),filter_column='role',filter_values=('administrator','operator','viewer'))
            filters=[(k,'role.'+k) for k in ('administrator','operator','viewer')]
        elif section=='sessions':
            now=time.time();deadline=now-projects.base_settings.session_idle_seconds
            source=f"(SELECT s.id,s.user_id,u.username,s.created_at,s.last_seen,s.expires_at,CASE WHEN s.revoked_at IS NOT NULL THEN 'revoked' WHEN s.expires_at<={now} OR s.last_seen<={deadline} THEN 'expired' ELSE 'active' END AS status FROM sessions s JOIN users u ON u.id=s.user_id)"
            columns=[C('id','common.id'),C('username','auth.username'),C('status','common.status','state'),C('created_at','common.created','epoch'),C('last_seen','common.last_seen','epoch'),C('expires_at','common.expires','epoch')]
            table=sql_page(conn,request,source,columns,where='' if admin else 'user_id=?',params=() if admin else (user['user_id'],),search=('username',),filter_column='status',filter_values=('active','expired','revoked'))
            filters=[(k,'state.'+k) for k in ('active','expired','revoked')]
        elif section=='history':
            source='(SELECT a.*,u.username FROM user_audit a LEFT JOIN users u ON u.id=a.actor_id)'
            columns=[C('id','common.id'),C('created_at','common.date','date'),C('username','auth.username'),C('event','common.actions','event'),C('result','common.result','outcome'),C('target_id','common.target'),C('project_id','common.project'),C('peer','common.ip'),C('details','common.details','details')]
            table=sql_page(conn,request,source,columns,where='' if admin else '(actor_id=? OR target_id=?)',params=() if admin else (user['user_id'],user['user_id']),search=('username','event','peer'),filter_column='result',filter_values=('success','failed','denied','started','authorized'))
            filters=[(k,'outcome.'+k) for k in ('success','failed','denied','started','authorized')]
        else:table=None;filters=[]
        grants=[dict(r) for r in conn.execute('SELECT * FROM project_access')] if admin else []
    return dict(section=section,table=table,filters=filters,grants=grants,network=auth.state()['network_enabled'] if admin else None)
