"""Durable SQLite queue, single dispatcher, bounded workers and persisted schedules."""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import logging
import sqlite3
import threading
import time
import uuid
from . import projects,auth,backups,services,db
from .backup_storage import BackupError,private_dir,project_lock,capacity

TASKS={'backup','snapshot','verify','retention'}
TERMINAL={'succeeded','failed','cancelled','interrupted'}
logger=logging.getLogger(__name__)


def log_failure(jid,code,exc):
    """Log bounded code locations, never exception messages, locals or source contents."""
    locations=[];tb=exc.__traceback__
    root=Path(__file__).resolve().parent
    while tb is not None:
        filename=Path(tb.tb_frame.f_code.co_filename)
        if filename.is_relative_to(root):
            locations.append(filename.relative_to(root).as_posix()+':'+str(tb.tb_lineno))
        tb=tb.tb_next
    logger.error('Job %s failed: code=%s exception=%s locations=%s',jid,code,
                 type(exc).__name__,','.join(locations[-12:]))


def allowed(conn,actor_id,pid,admin=False,version=None):
    user=conn.execute('SELECT * FROM users WHERE id=? AND enabled=1',(actor_id,)).fetchone()
    if not user or version is not None and user['auth_version']!=version:return False
    if admin:return user['role']=='administrator'
    return user['role']=='administrator' or user['role']=='operator' and conn.execute('SELECT 1 FROM project_access WHERE user_id=? AND project_id=?',(actor_id,pid)).fetchone() is not None


def enqueue(pid,actor,task='backup',kind='full',description='',point_id=None,conn=None,schedule=None,scheduled_for=None):
    if os.name!='posix':raise BackupError('platform')
    if task not in TASKS or kind not in ('full','incremental','checkpoint') or len(description)>4000:raise BackupError('policy')
    if task=='verify' and point_id is not None and (len(point_id)!=32 or any(c not in '0123456789abcdef' for c in point_id)):raise BackupError('policy')
    if conn is None:
        with projects.registry() as c:return enqueue(pid,actor,task,kind,description,point_id,c,schedule,scheduled_for)
    if not allowed(conn,actor,pid,admin=task=='retention'):raise BackupError('access')
    user=conn.execute('SELECT auth_version FROM users WHERE id=?',(actor,)).fetchone()
    if not conn.execute('SELECT 1 FROM projects WHERE id=? AND enabled=1',(pid,)).fetchone():raise BackupError('access')
    # Limit pending work per project and globally to avoid an unbounded authenticated queue.
    if conn.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running')").fetchone()[0]>=100 or conn.execute("SELECT count(*) FROM jobs WHERE project_id=? AND state IN ('queued','running')",(pid,)).fetchone()[0]>=20:
        raise BackupError('queue_full')
    jid=uuid.uuid4().hex
    conn.execute("INSERT INTO jobs(id,project_id,actor_id,actor_version,task,kind,description,point_id,state,created_at,schedule_id,scheduled_for) VALUES(?,?,?,?,?,?,?,?,'queued',?,?,?)",
                 (jid,pid,actor,user['auth_version'],task,kind,description,point_id,time.time(),schedule,scheduled_for))
    return jid


def cancel(jid,pid,actor):
    with projects.registry() as conn:
        if not allowed(conn,actor,pid):raise BackupError('access')
        row=conn.execute('SELECT * FROM jobs WHERE id=? AND project_id=?',(jid,pid)).fetchone()
        if not row:raise BackupError('missing')
        if row['task'] in ('restore','restore_undo'):
            user=conn.execute('SELECT id AS user_id,role FROM users WHERE id=?',(actor,)).fetchone()
            from .restores import permitted
            if not permitted(conn,dict(user),pid):raise BackupError('restore_access')
            if row['state']=='queued':
                conn.execute("UPDATE restore_operations SET state=?,error_code='cancelled',updated_at=? WHERE id=?",
                             ('interrupted' if row['task']=='restore_undo' else 'failed',time.time(),row['restore_op_id']))
                if row['task']=='restore':
                    import json
                    previous=conn.execute('SELECT spec_json FROM restore_operations WHERE id=?',(row['restore_op_id'],)).fetchone()
                    predecessor=json.loads(previous[0]).get('recovery_of') if previous else None
                    if predecessor:conn.execute("UPDATE restore_operations SET state='interrupted',updated_at=? WHERE id=? AND state='superseded'",(time.time(),predecessor))
        conn.execute("UPDATE jobs SET cancel_requested=1,state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END,finished_at=CASE WHEN state='queued' THEN ? ELSE finished_at END WHERE id=? AND state IN ('queued','running')",(time.time(),jid))


def job_rows(pid):
    with projects.registry() as conn:
        return [dict(r) for r in conn.execute('SELECT * FROM jobs WHERE project_id=? ORDER BY created_at DESC LIMIT 100',(pid,))]


def job_page(pid,page=1):
    if type(page) is not int or not 1<=page<=1000000:raise BackupError('policy')
    with projects.registry() as conn:
        total=conn.execute('SELECT count(*) FROM jobs WHERE project_id=?',(pid,)).fetchone()[0]
        pages=max(1,(total+24)//25);page=min(page,pages)
        rows=[dict(r) for r in conn.execute('SELECT * FROM jobs WHERE project_id=? ORDER BY created_at DESC,id DESC LIMIT 25 OFFSET ?',(pid,(page-1)*25))]
    return dict(rows=rows,total=total,page=page,pages=pages)


def polled_jobs(pid):
    # A long-running job must remain visible even after many newer cancelled jobs.
    rows={r['id']:r for r in job_rows(pid)}
    with projects.registry() as conn:
        for r in conn.execute("SELECT * FROM jobs WHERE project_id=? AND state IN ('queued','running')",(pid,)):
            rows[r['id']]=dict(r)
    return list(rows.values())


def schedule(pid,actor,task,kind,interval,enabled,conn=None):
    if task not in TASKS or kind not in ('full','incremental') or interval not in (86400,604800):raise BackupError('policy')
    if conn is None:
        with projects.registry() as c:return schedule(pid,actor,task,kind,interval,enabled,c)
    if not allowed(conn,actor,pid,admin=True):raise BackupError('access')
    conn.execute('INSERT INTO job_schedules(project_id,actor_id,task,kind,interval_seconds,next_run,enabled) VALUES(?,?,?,?,?,?,?) ON CONFLICT(project_id,task) DO UPDATE SET actor_id=excluded.actor_id,kind=excluded.kind,interval_seconds=excluded.interval_seconds,next_run=excluded.next_run,enabled=excluded.enabled',
                 (pid,actor,task,kind,interval,time.time()+interval,int(bool(enabled))))


def due(now=None):
    now=time.time() if now is None else now
    with projects.registry() as conn:
        conn.execute('BEGIN IMMEDIATE')
        rows=conn.execute('SELECT s.* FROM job_schedules s JOIN projects p ON p.id=s.project_id WHERE s.enabled=1 AND s.next_run<=? AND p.enabled=1',(now,)).fetchall()
        for s in rows:
            existing=conn.execute('SELECT 1 FROM jobs WHERE schedule_id=? AND scheduled_for=?',(s['id'],s['next_run'])).fetchone()
            if not existing:
                try:enqueue(s['project_id'],s['actor_id'],s['task'],s['kind'],conn=conn,schedule=s['id'],scheduled_for=s['next_run'])
                except BackupError as exc:
                    if exc.code=='queue_full':continue
                    conn.execute('UPDATE job_schedules SET enabled=0 WHERE id=?',(s['id'],));continue
            # Collapse missed intervals to one run, advance from the original UTC grid.
            advance=int((now-s['next_run'])//s['interval_seconds'])+1
            conn.execute('UPDATE job_schedules SET next_run=next_run+? WHERE id=?',(advance*s['interval_seconds'],s['id']))


class JobProgress:
    def __init__(self,jid,stop=None):self.id=jid;self.stop=stop;self.last=0
    def tick(self,force=False):
        now=time.monotonic()
        if not force and now-self.last<0.15:return
        self.last=now
        if self.stop is not None and self.stop.is_set():raise BackupError('shutdown')
        with projects.registry() as conn:
            row=conn.execute('SELECT * FROM jobs WHERE id=?',(self.id,)).fetchone()
            if row['cancel_requested']:raise BackupError('cancelled')
            if not allowed(conn,row['actor_id'],row['project_id'],admin=row['task']=='retention',version=row['actor_version']):raise BackupError('access')
            if row['task'] in ('restore','restore_undo'):
                from .restores import check_job
                check_job(conn,row)
            if not conn.execute('SELECT 1 FROM projects WHERE id=? AND enabled=1',(row['project_id'],)).fetchone():raise BackupError('access')
            conn.execute("UPDATE jobs SET heartbeat=? WHERE id=? AND state='running'",(time.time(),self.id))
    def update(self,**values):
        valid={'progress_bytes','total_bytes','progress_files','total_files'}
        if not values or set(values)-valid:raise BackupError('policy')
        self.tick()
        with projects.registry() as conn:conn.execute('UPDATE jobs SET '+','.join(k+'=?' for k in values)+' WHERE id=?',(*values.values(),self.id))


def execute(jid,stop=None):
    """A queued job is claimed once in SQLite; project lock is the cross-process arbiter."""
    with projects.registry() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row=conn.execute("SELECT * FROM jobs WHERE id=? AND state='queued' AND not_before<=?",(jid,time.time())).fetchone()
        if not row:return False
        item=dict(row)
        conn.execute("UPDATE jobs SET state='running',started_at=?,heartbeat=?,attempts=attempts+1 WHERE id=?",(time.time(),time.time(),jid))
    progress=JobProgress(jid,stop);token=None;result=None;error='internal';state='failed'
    try:
        cfg=projects.project_settings(projects.get_project(item['project_id'],include_disabled=True))
        token=projects.current_settings.set(cfg)
        progress.tick(force=True)
        if item['task']=='backup':
            result=backups.create(item['kind'],item['description'],item['actor_id'],jid,progress.tick,progress.update,
                                  commit_check=lambda:progress.tick(force=True))['point_id']
        elif item['task']=='verify':
            if item['point_id']:backups.verify(item['point_id'],progress.tick)
            else:
                for p in backups.points():
                    if p['state']=='available':progress.tick();backups.verify(p['id'],progress.tick)
        elif item['task']=='snapshot':
            services.run_analysis(item['description'],tick=progress.tick)
        elif item['task']=='retention':backups.retention(progress.tick)
        elif item['task'] in ('restore','restore_undo'):
            from . import restores
            if item['task']=='restore':
                restores.execute(item['restore_op_id'],progress.tick,progress.update,lambda:progress.tick(force=True))
            else:
                restores.execute_undo(item['restore_op_id'],item['point_id'],progress.tick,progress.update,lambda:progress.tick(force=True))
        else:raise BackupError('policy')
        state='succeeded';error=''
    except BackupError as exc:
        error=exc.code
        state='cancelled' if error=='cancelled' else ('interrupted' if error in ('shutdown','restore_interrupted') else 'failed')
        if error in ('busy','source_changed','sqlite_unstable') and item['attempts']<2:state='queued'
    except (OSError,sqlite3.DatabaseError) as exc:
        state='failed';error='io';log_failure(jid,error,exc)
    except Exception as exc:
        # Persist no exception text: source contents/credentials must not reach job logs.
        state='failed';error='internal';log_failure(jid,error,exc)
    finally:
        if item['task'] in ('restore','restore_undo') and state not in ('succeeded','queued'):
            from . import restores
            try:
                op=restores.operation(item['restore_op_id'])
                if item['task']=='restore' and op['state']=='queued':
                    restores.settle(op['id'],'failed',error)
                elif op['state'] not in ('committed','rolled_back','failed','superseded'):
                    restores.update(op['id'],state='interrupted',error_code='restore_interrupted')
            except (OSError,ValueError,sqlite3.DatabaseError):pass
        if token is not None:projects.current_settings.reset(token)
        with projects.registry() as conn:
            conn.execute('UPDATE jobs SET state=?,finished_at=?,heartbeat=?,error_code=?,result_point_id=?,not_before=? WHERE id=?',
                         (state,None if state=='queued' else time.time(),time.time(),error,result,time.time()+min(60,2**(item['attempts']+1)),jid))
            auth.event(conn,item['actor_id'],'job_'+state,'local-worker',
                       'success' if state=='succeeded' else ('started' if state=='queued' else 'failed'),project=item['project_id'])
    return True


def recover_interrupted():
    """Only called by the process holding the dispatcher lock. Never repeats a running job."""
    with projects.registry() as conn:running=[dict(r) for r in conn.execute("SELECT * FROM jobs WHERE state='running'")]
    for item in running:
        result=None
        try:
            cfg=projects.project_settings(projects.get_project(item['project_id'],include_disabled=True))
            token=projects.current_settings.set(cfg)
            try:
                if item['task'] in ('restore','restore_undo'):
                    from . import restores
                    result=item['restore_op_id'] if restores.reconcile(item['id'],item['restore_op_id'],item['task']=='restore_undo') else None
                else:
                    with project_lock(item['project_id']):
                        if cfg.db_path.exists():
                            db.init_db()
                            with db.db_conn() as conn:
                                row=conn.execute('SELECT id FROM backup_points WHERE job_id=?',(item['id'],)).fetchone()
                            if row:
                                backups.verified_chain(row[0]);result=row[0]
            finally:projects.current_settings.reset(token)
        except (BackupError,OSError,ValueError,sqlite3.DatabaseError):pass
        with projects.registry() as conn:
            conn.execute("UPDATE jobs SET state=?,error_code=?,finished_at=?,result_point_id=? WHERE id=? AND state='running'",
                         ('succeeded' if result else 'interrupted','' if result else 'interrupted',time.time(),result,item['id']))
    # Resume only already-journaled application archive deletion, never source restoration.
    for project in projects.list_projects(include_disabled=True):
        cfg=projects.project_settings(project)
        if not cfg.db_path.exists():continue
        token=projects.current_settings.set(cfg)
        try:
            with project_lock(project['id']):
                db.init_db()
                for p in backups.points():
                    if p['state']=='deleting':backups.finish_deletion(p)
        except (BackupError,OSError,ValueError,sqlite3.DatabaseError):pass
        finally:projects.current_settings.reset(token)


def reconcile_failed_worker(jid):
    """A finished Future can outlive a failed registry status commit. Never run it twice."""
    with projects.registry() as conn:
        item=conn.execute('SELECT * FROM jobs WHERE id=?',(jid,)).fetchone()
        if not item or item['state']!='running':return True
        item=dict(item)
    cfg=projects.project_settings(projects.get_project(item['project_id'],include_disabled=True))
    token=projects.current_settings.set(cfg);result=None
    try:
        if item['task'] in ('restore','restore_undo'):
            from . import restores
            result=item['restore_op_id'] if restores.reconcile(jid,item['restore_op_id'],item['task']=='restore_undo') else None
            with projects.registry() as conn:
                conn.execute("UPDATE jobs SET state=?,error_code=?,finished_at=?,result_point_id=? WHERE id=? AND state='running'",
                             ('succeeded' if result else 'interrupted','' if result else 'restore_interrupted',time.time(),result,jid))
            return True
        try:
            with project_lock(item['project_id']),capacity():
                if cfg.db_path.exists():
                    db.init_db()
                    with db.db_conn() as conn:
                        row=conn.execute('SELECT id FROM backup_points WHERE job_id=?',(jid,)).fetchone()
                    if row:backups.verified_chain(row[0]);result=row[0]
        except BackupError as exc:
            if exc.code=='busy':return False
    finally:projects.current_settings.reset(token)
    with projects.registry() as conn:
        state='succeeded' if result else 'interrupted'
        conn.execute("UPDATE jobs SET state=?,error_code=?,finished_at=?,result_point_id=? WHERE id=? AND state='running'",
                     (state,'' if result else 'interrupted',time.time(),result,jid))
        auth.event(conn,item['actor_id'],'job_'+state,'local-worker','success' if result else 'failed',project=item['project_id'])
    return True


class Runner:
    def __init__(self):self.stop=threading.Event();self.thread=None;self.fd=None
    def start(self):
        if os.name!='posix':return  # Keep login/config usable; filesystem engine fails closed.
        import fcntl
        root=private_dir(projects.base_settings.data_dir/'operation-locks')
        self.fd=os.open(root/'dispatcher.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:os.close(self.fd);self.fd=None;return
        recover_interrupted()
        self.thread=threading.Thread(target=self.loop,name='ptm-dispatcher',daemon=True);self.thread.start()
    def loop(self):
        with ThreadPoolExecutor(max_workers=projects.base_settings.max_parallel_jobs,thread_name_prefix='ptm-job') as pool:
            futures={}
            while not self.stop.is_set():
                try:
                    for future,(_,jid) in list(futures.items()):
                        if not future.done():continue
                        try:future.result()
                        except BaseException:
                            # A worker's SystemExit must not kill the dispatcher or imply success.
                            if not reconcile_failed_worker(jid):continue
                        del futures[future]
                    due()
                    with projects.registry() as conn:
                        rows=conn.execute("SELECT id,project_id FROM jobs WHERE state='queued' AND not_before<=? ORDER BY created_at LIMIT 100",(time.time(),)).fetchall()
                    busy={pid for pid,_ in futures.values()}
                    for row in rows:
                        if len(futures)>=projects.base_settings.max_parallel_jobs:break
                        if row['project_id'] in busy:continue
                        future=pool.submit(execute,row['id'],self.stop);futures[future]=(row['project_id'],row['id']);busy.add(row['project_id'])
                except (OSError,ValueError,sqlite3.DatabaseError):
                    pass  # durable queue remains untouched; next bounded iteration retries storage
                self.stop.wait(projects.base_settings.job_poll_seconds)
    def close(self):
        self.stop.set()
        # Do not release leadership while old workers still run.
        if self.thread:self.thread.join()
        if self.fd is not None:os.close(self.fd);self.fd=None
