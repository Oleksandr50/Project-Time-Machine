"""Read-only screens and bounded table views over existing project histories."""
from pathlib import Path
import hashlib
import difflib
import json
import os
import sqlite3
import stat
from fastapi import APIRouter,Request,HTTPException
from . import auth,projects,services,db,i18n
from .config import settings
from .archives import availability
from .filesystem import open_directory
from .tables import column as C,sql_page,memory_page,like
from .ui import render,clean_query
from urllib.parse import urlencode

router=APIRouter()
SNAPSHOT_COLS=[C('id','common.id'),C('created_at','common.date','date'),C('description','common.description'),C('content_status','common.type','state'),C('total_files','common.files','number'),C('python_files','common.python','number'),C('functions_count','common.functions','number'),C('classes_count','common.classes','number'),C('changes_from_prev','common.changes','number')]
BACKUP_COLS=[C('id','common.id'),C('created_at','common.date','date'),C('kind','common.type','backup_kind'),C('snapshot_id','common.snapshot'),C('archive_path','common.path','path'),C('archive_size','common.size','bytes'),C('sha256','common.hash','hash'),C('availability','backup.availability','state'),C('download','delete.actions','backup_actions')]
EVENT_COLS=[C('created_at','common.date','date'),C('event_type','common.type','event'),C('path_a','common.path','path'),C('path_b','compare.b','path'),C('comment','common.description','message')]
FILE_COLS=[C('path','common.path','file_link'),C('file_type','common.type','file'),C('size','common.size','bytes'),C('mtime','common.modified','epoch'),C('sha256','common.hash','hash'),C('lines','common.lines','number')]
FUNCTION_COLS=[C('risk_level','audit.risk','risk'),C('qualname','common.name'),C('path','common.path','path'),C('lineno','common.line','number'),C('kind','common.type','entity'),C('signature','audit.signature','path'),C('analyzer_id','analysis.adapter'),C('file_category','analysis.scope','scope')]
AUDIT_COLS=[C('severity','audit.severity','severity'),C('category','common.category','audit_category'),C('path','common.path','path'),C('occurrences','common.lines','audit_lines'),C('message','audit.message','audit_message'),C('review_status','audit.review','audit_status'),C('review_key','audit.review','audit_review')]


def selected_snapshot(conn,request,analysis=False):
    value=request.query_params.get('snapshot_id')
    try:sid=int(value) if value else None
    except ValueError:raise HTTPException(400,'error.validation')
    if sid is None:
        row=conn.execute('SELECT id FROM snapshots '+('WHERE backup_point_id IS NULL ' if analysis else '')+'ORDER BY id DESC LIMIT 1').fetchone()
        sid=row[0] if row else None
    if sid is None:return None
    if not conn.execute('SELECT 1 FROM snapshots WHERE id=?',(sid,)).fetchone():raise HTTPException(404,'Snapshot не найден')
    return sid


def snapshot_options(conn,selected=None):
    # A visible bounded picker; any historical ID can also be entered directly.
    result=[dict(r) for r in conn.execute('SELECT id,created_at FROM snapshots ORDER BY id DESC LIMIT 100')]
    if selected and selected not in [r['id'] for r in result]:
        row=conn.execute('SELECT id,created_at FROM snapshots WHERE id=?',(selected,)).fetchone()
        if row:result.append(dict(row))
    return result


def collection(request,title,table,**ctx):return render(request,'collection.html',title_key=title,table=table,**ctx)


@router.get('/')
def dashboard(request:Request):
    totals=dict(projects=len(request.state.projects),snapshots=0,archives=0,volume=0,missing=0,recoverable=0)
    last_analysis=None;last_backup=None;recent=[];warnings=[]
    for project in request.state.projects:
        cfg=projects.project_settings(project)
        if not cfg.db_path.exists():continue
        conn=None
        try:
            conn=sqlite3.connect(cfg.db_path.resolve().as_uri()+'?mode=ro',uri=True,timeout=2);conn.row_factory=sqlite3.Row
            n,last=conn.execute('SELECT count(*),max(created_at) FROM snapshots').fetchone()
            totals['snapshots']+=n
            columns={r[1] for r in conn.execute('PRAGMA table_info(snapshots)')}
            if 'backup_point_id' in columns:
                last=conn.execute('SELECT max(created_at) FROM snapshots WHERE backup_point_id IS NULL').fetchone()[0]
            if last:last_analysis=max(last_analysis or last,last)
            # A declared status is reported separately; no legacy snapshot is promoted.
            totals['recoverable']+=conn.execute("SELECT count(*) FROM snapshots WHERE content_status='recoverable'").fetchone()[0]
            for b in conn.execute('SELECT archive_path,archive_size,created_at FROM backups'):
                last_backup=max(last_backup or b['created_at'],b['created_at'])
                if availability_for(b['archive_path'],cfg)=='Available':totals['archives']+=1;totals['volume']+=b['archive_size']
                elif not Path(b['archive_path']).exists():totals['missing']+=1
            for row in conn.execute('SELECT * FROM file_events ORDER BY created_at DESC,id DESC LIMIT 100'):
                recent.append(dict(row,project_name=project['name'],project_id=project['id']))
            row=conn.execute('SELECT id FROM snapshots '+('WHERE backup_point_id IS NULL ' if 'backup_point_id' in columns else '')+'ORDER BY id DESC LIMIT 1').fetchone()
            if row:
                for warning in conn.execute("SELECT a.severity,a.path,a.message,a.rowid AS id,coalesce((SELECT min(s.created_at) FROM audit_findings f JOIN snapshots s ON s.id=f.snapshot_id WHERE f.fingerprint=a.fingerprint AND a.fingerprint!=''),snap.created_at) AS discovered FROM audit_findings a JOIN snapshots snap ON snap.id=a.snapshot_id WHERE a.snapshot_id=? AND a.severity IN ('critical','high') ORDER BY discovered DESC,a.rowid DESC LIMIT 100",(row[0],)):
                    warnings.append(dict(warning,project_name=project['name'],project_id=project['id']))
        except (sqlite3.Error,OSError):warnings.append({'message':'dashboard.db_error','severity':'info','path':'','project_name':project['name']})
        finally:
            if conn:conn.close()
    recent=sorted(recent,key=lambda r:(r['created_at'],r['project_id'],r['id']),reverse=True)[:100]
    warnings=sorted(warnings,key=lambda r:(r.get('discovered',''),r.get('project_id',0),r.get('id',0)),reverse=True)
    from . import jobs
    dashboard_jobs=sorted([row for p in request.state.projects for row in jobs.polled_jobs(p['id'])],
                          key=lambda r:(r['created_at'],r['id']),reverse=True)[:100]
    return render(request,'index.html',title_key='nav.dashboard',totals=totals,last_analysis=last_analysis,last_backup=last_backup,recent=recent,warnings=warnings[:100],dashboard_jobs=dashboard_jobs)


def availability_for(path,cfg):
    token=projects.current_settings.set(cfg)
    try:return availability(path)
    finally:projects.current_settings.reset(token)


@router.get('/projects')
def project_page(request:Request):
    rows=request.state.all_projects
    cols=[C('id','common.id'),C('name','common.name','project_link'),C('description','common.description'),C('category','common.category'),C('path','common.path','path'),C('status','common.status','state'),C('updated_at','common.updated','date')]
    table=memory_page(request,rows,cols,default='name')
    return render(request,'projects.html',title_key='nav.projects',table=table)


@router.get('/snapshots')
def snapshots(request:Request):
    services.ensure_db()
    with db.db_conn() as conn:
        page=sql_page(conn,request,'snapshots',SNAPSHOT_COLS,search=('description',),filter_column='content_status',filter_values=('metadata_only','recoverable','incomplete','unavailable'))
    return collection(request,'nav.snapshots',page,hint='snapshots.hint',filters=[(c,'state.'+c) for c in ('metadata_only','recoverable','incomplete','unavailable')],snapshot_action=True)


@router.get('/timeline')
def timeline(request:Request):
    services.ensure_db()
    with db.db_conn() as conn:
        kinds=('created','deleted','modified','renamed','hash_changed','size_changed')
        page=sql_page(conn,request,'file_events',EVENT_COLS,default='created_at',search=('path_a','path_b','comment'),filter_column='event_type',filter_values=kinds)
    return collection(request,'nav.timeline',page,filters=[(c,'event.'+c) for c in kinds])


@router.get('/backups')
def backups(request:Request):
    services.ensure_db()
    with db.db_conn() as conn:
        rows=[dict(r) for r in conn.execute('SELECT b.*,p.id AS point_id,p.kind,p.parent_id,p.key_id,p.protected,p.state,p.last_error,p.verified_at FROM backups b LEFT JOIN backup_points p ON p.backup_id=b.id')]
    for row in rows:row['availability']=availability(row['archive_path']);row['download']=row['id'] if row['availability']=='Available' else None
    value=request.query_params.get('kind','')
    if value not in ('','Available','Missing','Unavailable'):raise HTTPException(400,'error.table')
    if value:rows=[r for r in rows if r['availability']==value]
    page=memory_page(request,rows,BACKUP_COLS);page.filter_value=value
    from . import jobs
    from . import backups as engine
    with projects.registry() as conn:
        schedules=[dict(r) for r in conn.execute('SELECT * FROM job_schedules WHERE project_id=?',(settings.project_id,))]
    try:job_page=jobs.job_page(settings.project_id,int(request.query_params.get('jobs_page','1')))
    except ValueError:raise HTTPException(400,'error.table')
    return render(request,'backups.html',title_key='nav.backups',table=page,filters=[(v,'state.'+v) for v in ('Available','Missing','Unavailable')],
                  policy=engine.policy(settings.project_id),schedules=schedules,jobs=job_page['rows'],job_history=job_page,
                  key_ids=sorted(projects.base_settings.encryption_keys),points=engine.points())


@router.get('/files')
def files(request:Request):
    services.ensure_db()
    with db.db_conn() as conn:
        sid=selected_snapshot(conn,request);snaps=snapshot_options(conn,sid)
        prefix=request.query_params.get('prefix','')[:500]
        where="snapshot_id=? AND is_secret=0 AND path LIKE ? ESCAPE '\\'"
        page=sql_page(conn,request,'snapshot_files',FILE_COLS,default='path',where=where,params=(sid or -1,like(prefix)[1:] if prefix else '%'),search=('path',),filter_column='file_type',filter_values=('python','text','binary','sqlite','log'))
    return collection(request,'nav.files',page,snapshot_id=sid,snapshots=snaps,show_prefix=True,filters=[(k,'file.'+k) for k in ('python','text','binary','sqlite','log')])


@router.get('/functions')
def functions(request:Request):
    services.ensure_db()
    with db.db_conn() as conn:
        sid=selected_snapshot(conn,request,analysis=True);snaps=snapshot_options(conn,sid)
        kind=request.query_params.get('entity','functions')
        if kind not in ('functions','classes','all'):raise ValueError('error.validation')
        where='snapshot_id=?';params=[sid or -1]
        if kind!='all':where+=" AND kind "+("='class'" if kind=='classes' else "IN ('function','async_function')")
        scope=request.query_params.get('scope','')
        if scope not in ('','active','archived','generated','dependencies'):raise ValueError('error.validation')
        source="(SELECT e.*,coalesce(f.file_category,'active') AS file_category FROM python_entities e LEFT JOIN snapshot_files f ON f.snapshot_id=e.snapshot_id AND f.path=e.path)"
        if scope:where+=' AND file_category=?';params.append(scope)
        page=sql_page(conn,request,source,FUNCTION_COLS,default='path',where=where,params=params,search=('name','qualname','path'),filter_column='risk_level',filter_values=('green','yellow','red'))
        summary=conn.execute('SELECT category_metrics,analysis_info FROM snapshots WHERE id=?',(sid,)).fetchone()
    return render(request,'analysis.html',title_key='nav.analysis',table=page,snapshot_id=sid,snapshots=snaps,
        metrics=json.loads(summary[0]) if summary else {},analysis_info=json.loads(summary[1]) if summary else {},
        filters=[(k,'risk.'+k) for k in ('green','yellow','red')],entity=kind,scope=scope)


def audit_data(conn,request):
    from .audit_service import view,bounded
    view(conn);bounded(conn)
    sid=selected_snapshot(conn,request,analysis=True);snaps=snapshot_options(conn,sid)
    baseline=request.query_params.get('baseline','')
    try:baseline=int(baseline) if baseline else None
    except ValueError:raise ValueError('error.validation') from None
    if baseline is not None and not conn.execute('SELECT 1 FROM snapshots WHERE id=?',(baseline,)).fetchone():raise HTTPException(404,'Snapshot не найден')
    change=request.query_params.get('audit_change','new' if request.query_params.get('new_only')=='1' else '')
    if change not in ('','new','resolved','persistent'):raise ValueError('error.validation')
    where='snapshot_id=?';params=[sid or -1]
    if change:
        if baseline is None:raise ValueError('audit.baseline_required')
        other=baseline
        if change=='resolved':params=[baseline];other=sid or -1
        where+=' AND '+('' if change=='persistent' else 'NOT ')+'EXISTS (SELECT 1 FROM audit_view old WHERE old.snapshot_id=? AND old.review_key=audit_view.review_key)';params.append(other)
    category=request.query_params.get('category','')
    if category:where+=' AND category=?';params.append(category[:100])
    state=request.query_params.get('review','')
    if state not in ('','open','false_positive'):raise ValueError('error.validation')
    if state:where+=' AND review_status=?';params.append(state)
    return sid,snaps,baseline,where,params


@router.get('/audit')
def audit(request:Request):
    services.ensure_db()
    with db.db_conn() as conn:
        sid,snaps,baseline,where,params=audit_data(conn,request)
        groups=[dict(r) for r in conn.execute('SELECT category,count(*) AS count FROM audit_view WHERE snapshot_id=? GROUP BY category ORDER BY category',(sid or -1,))]
        counts={r[0]:r[1] for r in conn.execute('SELECT severity,count(*) FROM audit_view WHERE snapshot_id=? GROUP BY severity',(sid or -1,))}
        comparison=None
        if baseline is not None:
            current={r[0] for r in conn.execute('SELECT review_key FROM audit_view WHERE snapshot_id=?',(sid or -1,))}
            previous={r[0] for r in conn.execute('SELECT review_key FROM audit_view WHERE snapshot_id=?',(baseline,))}
            comparison=dict(new=len(current-previous),resolved=len(previous-current),persistent=len(current&previous))
        page=sql_page(conn,request,'audit_view',AUDIT_COLS,default='severity',where=where,params=params,search=('path','message','rule_id'),filter_column='severity',filter_values=('critical','high','medium','low','info'),
            sort_expressions={'severity':"CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"})
    return render(request,'audit.html',title_key='nav.audit',table=page,snapshot_id=sid,snapshots=snaps,baseline=baseline,groups=groups,counts=counts,comparison=comparison,export_url='/audit/export?'+urlencode(dict(clean_query(request),project_id=settings.project_id,snapshot_id=sid)),filters=[(k,'severity.'+k) for k in ('critical','high','medium','low','info')])


@router.post('/audit/review')
def audit_review(request:Request):
    from .audit_service import review,bounded
    form=request.state.form
    try:sid=int(form.get('snapshot_id',''))
    except ValueError:raise ValueError('error.validation') from None
    services.ensure_db()
    with db.db_conn() as conn:
        bounded(conn);review(conn,sid,form.get('fingerprint',''),form.get('status',''),request.state.user['user_id'])
    from fastapi.responses import RedirectResponse
    from urllib.parse import urlencode
    return RedirectResponse('/audit?'+urlencode(dict(project_id=settings.project_id,snapshot_id=sid)),status_code=303)


@router.get('/audit/export')
def audit_export(request:Request):
    from .redaction import redact
    from fastapi.responses import JSONResponse
    services.ensure_db()
    with db.db_conn() as conn:
        sid,snaps,baseline,where,params=audit_data(conn,request)
        # Mirror visible severity/search filters, bounded export without raw excerpts.
        severity=request.query_params.get('kind','')
        if severity:
            if severity not in ('critical','high','medium','low','info'):raise ValueError('error.validation')
            where+=' AND severity=?';params.append(severity)
        q=request.query_params.get('q','')[:300]
        if q:where+=" AND (path LIKE ? ESCAPE '\\' OR message LIKE ? ESCAPE '\\' OR rule_id LIKE ? ESCAPE '\\')";params.extend([like(q)]*3)
        rows=conn.execute('SELECT snapshot_id,severity,category,path,lineno,message,why,fix,review_status,rule_id,review_key FROM audit_view WHERE '+where+' ORDER BY severity,path,lineno LIMIT 10001',params).fetchall()
        result=[];size=0;truncated=len(rows)>10000
        for row in rows[:10000]:
            item={k:redact(i18n.message(v)) if isinstance(v,str) and k in ('message','why','fix') else redact(v) if isinstance(v,str) else v for k,v in dict(row).items()}
            size+=len(json.dumps(item).encode())
            if size>2*1024*1024:truncated=True;break
            result.append(item)
    return JSONResponse(dict(format_version=1,project_id=settings.project_id,snapshot_id=sid,baseline=baseline,unconfirmed=True,truncated=truncated,findings=result),headers={'Content-Disposition':'attachment; filename="audit-'+str(sid)+'.json"'})


@router.get('/file')
def file_detail(request:Request,snapshot_id:int,path:str):
    if not path or path.startswith('/') or '\\' in path or '\x00' in path or '..' in Path(path).parts:raise HTTPException(400,'Некорректный путь')
    services.ensure_db()
    with db.db_conn() as conn:
        try:services.snapshot_summary(conn,snapshot_id);file=services.file_detail(conn,snapshot_id,path)
        except KeyError:raise HTTPException(404,'Файл не найден в выбранном snapshot')
    return render(request,'file.html',title_key='nav.files',file=file,snapshot_id=snapshot_id)


CHANGE_COLS=[C('path','common.path','compare_link'),C('change','common.type','change'),C('path_b','compare.b','path')]


@router.get('/compare')
def compare(request:Request,a:int|None=None,b:int|None=None):
    services.ensure_db()
    with db.db_conn() as conn:
        snaps=snapshot_options(conn,a)
        if b and b not in [s['id'] for s in snaps]:snaps+=snapshot_options(conn,b)[-1:]
        if not snaps:return render(request,'compare.html',title_key='nav.compare',snapshots=[],table=None,a_id=None,b_id=None)
        a=a if a is not None else snaps[min(1,len(snaps)-1)]['id'];b=b if b is not None else snaps[0]['id']
        try:services.snapshot_summary(conn,a);services.snapshot_summary(conn,b)
        except KeyError:raise HTTPException(404,'Snapshot не найден')
        diff=services.compare(conn,a,b)
    renamed_old={x for x,_ in diff['renames']};renamed_new={x for _,x in diff['renames']}
    rows=[]
    for change,paths in [('added',diff['added']),('deleted',diff['deleted']),('modified',diff['modified'])]:
        for path in paths:
            if (change=='added' and path in renamed_new) or (change=='deleted' and path in renamed_old):continue
            rows.append({'path':path,'path_b':path if change=='modified' else '', 'change':change})
    rows += [{'path':old,'path_b':new,'change':'renamed'} for old,new in diff['renames']]
    value=request.query_params.get('kind','')
    if value not in ('','added','deleted','modified','renamed'):raise HTTPException(400,'error.table')
    prefix=request.query_params.get('prefix','')
    if prefix:rows=[r for r in rows if r['path'].startswith(prefix) or r['path_b'].startswith(prefix)]
    if value:rows=[r for r in rows if r['change']==value]
    page=memory_page(request,rows,CHANGE_COLS,default='path');page.filter_value=value
    return render(request,'compare.html',title_key='nav.compare',snapshots=snaps,table=page,a_id=a,b_id=b,filters=[(k,'compare.'+k) for k in ('added','deleted','modified','renamed')],show_prefix=True)


def stored_text(conn,sid,path):
    row=conn.execute('SELECT f.is_secret,f.file_type,f.sha256,c.object_digest,o.size,o.storage_key,o.verified_at FROM snapshot_files f LEFT JOIN snapshot_content c ON c.snapshot_id=f.snapshot_id AND c.path=f.path LEFT JOIN content_objects o ON o.digest=c.object_digest WHERE f.snapshot_id=? AND f.path=?',(sid,path)).fetchone()
    if not row or not row['object_digest'] or not row['verified_at']:return None,'compare.no_content'
    if row['is_secret']:return None,'files.secret'
    if row['file_type'] in ('binary','sqlite') or row['size']>1024*1024:return None,'compare.binary'
    key=Path(row['storage_key'])
    if key.is_absolute() or '..' in key.parts or not key.parts or '\\' in str(key):return None,'compare.integrity'
    try:
        with open_directory(settings.content_dir) as start:
            fd=os.dup(start)
            try:
                for part in key.parts[:-1]:
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
                leaf=os.open(key.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
                with os.fdopen(leaf,'rb') as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):return None,'compare.integrity'
                    data=stream.read(1024*1024+1)
            finally:os.close(fd)
        digest=hashlib.sha256(data).hexdigest()
        if len(data)!=row['size'] or digest!=row['object_digest'] or digest!=row['sha256']:return None,'compare.integrity'
        return data.decode('utf-8'),'ok'
    except UnicodeDecodeError:return None,'compare.binary'
    except (OSError,ValueError):return None,'compare.integrity'


@router.get('/compare/text')
def text_compare(request:Request,a:int,b:int,path:str):
    if not path or path.startswith('/') or '\\' in path or '\x00' in path or '..' in Path(path).parts:raise HTTPException(400,'Некорректный путь')
    services.ensure_db()
    with db.db_conn() as conn:
        try:services.snapshot_summary(conn,a);services.snapshot_summary(conn,b)
        except KeyError:raise HTTPException(404,'Snapshot не найден')
        left=conn.execute('SELECT path,size,sha256,file_type FROM snapshot_files WHERE snapshot_id=? AND path=?',(a,path)).fetchone()
        right=conn.execute('SELECT path,size,sha256,file_type FROM snapshot_files WHERE snapshot_id=? AND path=?',(b,path)).fetchone()
        ta,sa=stored_text(conn,a,path);tb,sb=stored_text(conn,b,path)
    note=sa if sa!='ok' else sb
    lines=[]
    if left is None and right is not None and tb is not None:ta=''
    if right is None and left is not None and ta is not None:tb=''
    if ta is not None and tb is not None:
        from .redaction import redact
        ta,tb=redact(ta),redact(tb)
        if len(ta.splitlines())+len(tb.splitlines())>20000:note='compare.binary'
        else:
            for line in difflib.unified_diff(ta.splitlines(),tb.splitlines(),fromfile=f'#{a}',tofile=f'#{b}',n=3):
                lines.append({'text':line,'kind':'add' if line.startswith('+') else ('del' if line.startswith('-') else 'context')})
            note='' if lines else 'compare.identical_view'
    return render(request,'diff.html',title_key='compare.content',path=path,left=dict(left) if left else None,right=dict(right) if right else None,lines=lines,note=note,a_id=a,b_id=b)


@router.get('/settings')
def settings_page(request:Request):
    return render(request,'settings.html',title_key='nav.settings',roots=projects.base_settings.allowed_roots if request.state.user['role']=='administrator' else [])


@router.get('/logs')
@router.get('/logs/view')
def logs(request:Request,path:str|None=None,n:int=200):
    from .data_views import log_window,LEVELS
    from .backup_storage import project_lock
    result=None;rows=[]
    query=request.query_params.get('log_q','');level=request.query_params.get('level','')
    with project_lock(settings.project_id):
        if path is not None:result=log_window(path,n,query,level)
        from .scanner import open_source
        for item in services.list_logs():
            if services.is_secret_for_display(str(item.relative_to(settings.agent_root))):continue
            try:
                with open_source(item) as stream:st=os.fstat(stream.fileno())
                rows.append({'path':str(item),'size':st.st_size,'mtime':st.st_mtime})
            except OSError:continue
    page=memory_page(request,rows,[C('path','common.path','log_link'),C('size','common.size','bytes'),C('mtime','common.modified','epoch')],default='mtime')
    return render(request,'logs.html',title_key='nav.logs',table=page,content=result['content'] if result else None,log_result=result,current_path=path,n=n,log_query=query,level=level,levels=LEVELS)


@router.get('/sqlite')
def databases(request:Request):
    from .data_views import sqlite_inspect
    from .backup_storage import project_lock
    rows=[];database=None;path=request.query_params.get('path')
    from .scanner import open_source
    with project_lock(settings.project_id):
        for item in services.list_sqlite_files():
            if services.is_secret_for_display(str(item.relative_to(settings.agent_root))):continue
            try:
                with open_source(item) as stream:st=os.fstat(stream.fileno())
                rows.append({'path':str(item),'size':st.st_size,'mtime':st.st_mtime})
            except OSError:continue
        if path:
            try:page=int(request.query_params.get('records_page','1'));size=int(request.query_params.get('records_per_page','25'))
            except ValueError:raise ValueError('error.validation') from None
            database=sqlite_inspect(path,request.query_params.get('table'),page,size)
    page=memory_page(request,rows,[C('path','common.path','database_link'),C('size','common.size','bytes'),C('mtime','common.modified','epoch')],default='mtime')
    return render(request,'sqlite.html',title_key='nav.logs',table=page,database=database)


@router.get('/report')
def report(request:Request):
    path=settings.reports_dir/'current_state.md'
    if not path.is_file():raise HTTPException(404,"Отчёт ещё не создан. Нажмите 'Обновить анализ'.")
    from .redaction import redact
    content=redact(path.read_text(encoding='utf-8',errors='replace'))
    return render(request,'report.html',title_key='nav.report',content=content)
