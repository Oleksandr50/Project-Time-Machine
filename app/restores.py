"""Confirmed, journaled restore orchestration. No automatic source rollback."""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import time
import tempfile
import uuid
from . import projects,auth,db,backups,restore_fs as fs,restore_sources as sources
from .config import settings
from .backup_format import canonical
from .backup_storage import (BackupError,project_lock,capacity,ensure_space,read_private,
                             digest_stream,CHUNK,relative_name,private_dir)
from .filesystem import open_directory,inside,validate_project,private_fd,forbidden
from .restore_state import ACTIVE,ensure_clear
from .migrations import utcnow

EXPIRES=900


def permitted(conn,user,pid):
    return user['role']=='administrator' or user['role']=='operator' and conn.execute(
        'SELECT 1 FROM project_access WHERE user_id=? AND project_id=? AND can_restore=1',(user['user_id'],pid)).fetchone() is not None


def actor(conn,key,pid):
    user=auth.actor(conn,key)
    if not permitted(conn,user,pid):raise auth.AuthError(403,'engine.restore_access')
    return user


def operation(opid):
    with projects.registry() as conn:row=conn.execute('SELECT * FROM restore_operations WHERE id=? AND project_id=?',(opid,settings.project_id)).fetchone()
    if not row:raise BackupError('restore_missing')
    return dict(row)


def operations():
    with projects.registry() as conn:return [dict(r) for r in conn.execute('SELECT id,project_id,actor_id,job_id,state,created_at,updated_at,target_path,safety_point_id,recovery_point_id,error_code FROM restore_operations WHERE project_id=? ORDER BY created_at DESC',(settings.project_id,))]


def binding(cfg):
    return sources.fingerprint(dict(project_id=cfg.project_id,path=str(cfg.agent_root),db=str(cfg.db_path),
        allowed=[str(p) for p in cfg.allowed_roots],storage=sorted(str(p) for p in cfg.storage_roots),
        exclusions=list(cfg.exclusion_rules),policy=backups.policy(cfg.project_id)))


def confirm_token(raw,preview_id):
    return hmac.new(raw.encode('ascii'),('ptm-restore-v1:'+preview_id).encode('ascii'),hashlib.sha256).hexdigest()


def scoped(cfg,spec):
    return replace(cfg,agent_root=Path(spec['target']),exclusion_rules=tuple(spec['rules']))


def _in_scope(name,cfg,secret_policy):
    from .scanner import excluded
    from .analyzer import is_secret_path
    return not excluded(name,cfg) and not (secret_policy=='exclude' and is_secret_path(name))


def plan(source,current,cfg,mode,selection):
    desired={e['path']:dict(e) for e in source['entries'] if _in_scope(e['path'],cfg,source['secret_policy'])}
    if any(forbidden(cfg.agent_root/p) for p in desired):raise BackupError('unsafe_path')
    before={p:e for p,e in current['entries'].items()}
    selected=set(selection)
    if mode=='files':
        if not selected or len(selected)>1000 or any(p not in desired or desired[p]['type']!='file' for p in selected):
            raise BackupError('restore_selection')
        desired={p:e for p,e in desired.items() if p in selected}
        # Parents are added for new files; unrelated existing metadata is not rewritten.
        for name in list(desired):
            for parent in Path(name).parents:
                p=parent.as_posix()
                if p!='.' and p not in desired:
                    desired[p]=dict(path=p,type='dir',mode=before.get(p,{}).get('mode',0o755),mtime_ns=before.get(p,{}).get('mtime_ns',0))
        managed={p:e for p,e in before.items() if p in desired}
    else:managed={p:e for p,e in before.items() if _in_scope(p,cfg,source['secret_policy'])}
    # SQLite sidecars belong to the selected database and must not survive its replacement.
    sidecars=set()
    for p,e in list(desired.items()):
        if e.get('sqlite') or before.get(p,{}).get('sqlite'):
            for suffix in ('-wal','-shm','-journal'):
                name=p+suffix
                if name in before:
                    managed[name]=before[name];sidecars.add(name);desired.pop(name,None)
    remove=[];install=[];make=[];changes=[]
    for p,e in managed.items():
        new=desired.get(p)
        changed=(new is None or e['type']!=new['type'] or e['type']=='file' and
                 (e['sha256']!=new['sha256'] or e['mode']!=new['mode'] or e['mtime_ns']!=new['mtime_ns']))
        if changed:remove.append(p)
    for p,e in desired.items():
        old=before.get(p)
        changed=old is None or p in remove
        if changed:
            (make if e['type']=='dir' else install).append(p)
        if changed or old and e['type']=='dir' and (old['mode']!=e['mode'] or old['mtime_ns']!=e['mtime_ns']):
            changes.append(dict(path=p,change='added' if old is None else 'modified',type=e['type'],size=e.get('size',0),sha256=e.get('sha256','')))
    for p in remove:
        if p not in desired:changes.append(dict(path=p,change='deleted',type=managed[p]['type'],size=managed[p].get('size',0),sha256=managed[p].get('sha256','')))
    for p in remove:
        if managed[p]['type']=='dir':
            # Removing a directory may never carry preserved/unselected children into undo.
            with open_directory(cfg.agent_root/p) as fd:
                if any(p+'/'+name not in remove for name in os.listdir(fd)):raise BackupError('restore_scope')
    return dict(desired=desired,before=before,remove=sorted(remove,key=lambda p:(p.count('/'),p),reverse=True),
                make=sorted(make,key=lambda p:(p.count('/'),p)),install=sorted(install),changes=sorted(changes,key=lambda e:e['path']),sidecars=sorted(sidecars))


def _space(target,exists,source,plan):
    amount=sum(e.get('size',0) for e in source['entries'] if e['type']=='file')
    ensure_space(target if exists else target.parent,amount*2+1024*1024)
    private_dir(settings.temp_dir);ensure_space(settings.temp_dir,sum(e.get('size',0) for e in plan['before'].values())*3+amount)
    ensure_space(projects.base_settings.data_dir,len(canonical(plan))*2+len(plan['changes'])*8192+1024*1024)


def preview(user,raw,source_type,source_id,mode='full',destination='',selection=(),tick=lambda:None,recovery_of=None):
    if mode not in ('full','files','alternate') and not (mode=='recovery' and recovery_of):raise BackupError('restore_mode')
    cfg=projects.current_settings.get()
    with project_lock(cfg.project_id,restore_id=recovery_of),capacity():
        with projects.registry() as conn:actor(conn,user['digest'],cfg.project_id)
        source=sources.inspect(source_type,source_id,tick)
        target,exists,extra=fs.validate_target(cfg,mode,destination)
        if source.get('restore_context') and str(target)!=source['restore_context']['target'] and mode!='alternate':
            raise BackupError('restore_scope')
        from .restore_state import workspaces
        owned=[Path(p).relative_to(target).as_posix() for p in workspaces(cfg.project_id) if Path(p).is_relative_to(target)]
        rules=sorted(set(cfg.exclusion_rules)|set(source['exclusions'])|set(extra)|set(owned))
        scope_cfg=replace(cfg,agent_root=target,exclusion_rules=tuple(rules))
        selection=[relative_name(p) for p in selection]
        current=fs.state(scope_cfg,tick,source['secret_policy']) if exists else dict(root=None,entries={})
        details=plan(source,current,scope_cfg,mode,selection)
        if not exists and mode=='files':raise BackupError('restore_new_only')
        for p,e in current['entries'].items():
            if e['dev']!=current['root'][0]:raise BackupError('restore_mount')
        for e in details['desired'].values():
            if e['type']=='file' and not e['mode']&0o400 or e['type']=='dir' and e['mode']&0o500!=0o500:
                raise BackupError('restore_permissions')
        if not os.access(target if exists else target.parent,os.W_OK|os.X_OK):raise BackupError('restore_permissions')
        for path in details['remove']+details['make']+details['install']:
            parent=target/Path(path).parent
            while not parent.is_dir() and parent!=target.parent:parent=parent.parent
            with open_directory(parent):pass
            if not os.access(parent,os.W_OK|os.X_OK):raise BackupError('restore_permissions')
        _space(target,exists,source,details)
        spec=dict(action='restore',source=source,target=str(target),exists=exists,mode=mode,rules=rules,
                  selection=selection,current=current,plan=details,binding=binding(cfg),
                  parent_id=fs.root_id(target.parent),processes=fs.processes(target) if exists else dict(pids=[],complete=True))
        if recovery_of:spec['recovery_of']=recovery_of
        return save_preview(user,raw,spec)


def save_preview(user,raw,spec):
    encoded=canonical(spec)
    if len(encoded)>32*1024*1024:raise BackupError('format')
    ensure_space(projects.base_settings.data_dir,len(encoded)*3+1024*1024)
    preview_id=uuid.uuid4().hex;token=confirm_token(raw,preview_id)
    with projects.registry() as conn:
        current=actor(conn,user['digest'],settings.project_id)
        conn.execute('INSERT INTO restore_previews VALUES(?,?,?,?,?,?,?,?,?,?)',
                     (preview_id,settings.project_id,current['user_id'],current['digest'],current['auth_version'],
                      hashlib.sha256(token.encode()).hexdigest(),time.time(),time.time()+EXPIRES,None,encoded.decode()))
    return dict(id=preview_id,spec=spec,token=token)


def get_preview(user,raw,preview_id):
    with projects.registry() as conn:
        current=actor(conn,user['digest'],settings.project_id)
        row=conn.execute('SELECT * FROM restore_previews WHERE id=? AND project_id=? AND user_id=? AND session_digest=?',
                         (preview_id,settings.project_id,current['user_id'],current['digest'])).fetchone()
    if not row or row['used_at'] or row['expires_at']<time.time() or row['user_version']!=current['auth_version']:raise BackupError('restore_preview')
    return dict(id=preview_id,spec=json.loads(row['spec_json']),token=confirm_token(raw,preview_id))


def confirm(user,raw,preview_id,token,acknowledge,word):
    if acknowledge!='on' or word!='RESTORE':raise BackupError('restore_confirm')
    if len(token)!=64 or any(c not in '0123456789abcdef' for c in token):raise BackupError('restore_confirm')
    shown=get_preview(user,raw,preview_id)
    if not hmac.compare_digest(shown['token'],token):raise BackupError('restore_confirm')
    cfg=projects.current_settings.get()
    if shown['spec']['binding']!=binding(cfg):raise BackupError('restore_stale')
    opid=uuid.uuid4().hex
    with projects.registry() as conn:
        conn.execute('BEGIN IMMEDIATE')
        current=actor(conn,user['digest'],cfg.project_id)
        if conn.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running')").fetchone()[0]>=100:
            raise BackupError('queue_full')
        row=conn.execute('SELECT * FROM restore_previews WHERE id=?',(preview_id,)).fetchone()
        if not row or row['used_at'] or row['expires_at']<time.time() or row['session_digest']!=current['digest'] or row['user_version']!=current['auth_version']:
            raise BackupError('restore_preview')
        if not hmac.compare_digest(row['token_digest'],hashlib.sha256(token.encode()).hexdigest()):raise BackupError('restore_confirm')
        spec=shown['spec'];action=spec['action']
        active=conn.execute("SELECT id FROM restore_operations WHERE project_id=? AND state IN ('queued','preparing','applying','interrupted','undoing')",(cfg.project_id,)).fetchone()
        if action=='undo':
            if not active or active[0]!=spec['operation_id']:raise BackupError('restore_preview')
            opid=spec['operation_id'];jid=uuid.uuid4().hex
            state=conn.execute('SELECT state FROM restore_operations WHERE id=?',(opid,)).fetchone()[0]
            if state!='interrupted' or conn.execute("SELECT 1 FROM jobs WHERE restore_op_id=? AND state IN ('queued','running')",(opid,)).fetchone():
                raise BackupError('restore_pending')
            conn.execute("UPDATE restore_operations SET actor_id=?,actor_version=?,session_digest=?,state='undoing',updated_at=? WHERE id=?",
                         (current['user_id'],current['auth_version'],current['digest'],time.time(),opid))
            task='restore_undo'
        else:
            recovery=spec.get('recovery_of')
            if active and active[0]!=recovery:raise BackupError('restore_pending')
            if recovery:
                state=conn.execute('SELECT state FROM restore_operations WHERE id=?',(recovery,)).fetchone()
                if not state or state[0]!='interrupted' or conn.execute("SELECT 1 FROM jobs WHERE restore_op_id=? AND state IN ('queued','running')",(recovery,)).fetchone():
                    raise BackupError('restore_pending')
                conn.execute("UPDATE restore_operations SET state='superseded',updated_at=? WHERE id=?",(time.time(),recovery))
            jid=opid;task='restore'
            target=Path(spec['target']);parent=target if spec['exists'] else target.parent
            work=parent/(fs.WORK_PREFIX+opid)
            conn.execute("INSERT INTO restore_operations(id,project_id,actor_id,actor_version,session_digest,job_id,state,created_at,updated_at,target_path,work_path,nonce,spec_json) VALUES(?,?,?,?,?,?,'queued',?,?,?,?,?,?)",
                         (opid,cfg.project_id,current['user_id'],current['auth_version'],current['digest'],jid,time.time(),time.time(),str(target),str(work),secrets.token_hex(32),canonical(spec).decode()))
        conn.execute("INSERT INTO jobs(id,project_id,actor_id,actor_version,task,kind,state,created_at,restore_op_id,point_id) VALUES(?,?,?,?,?,'full','queued',?,?,?)",
                     (jid,cfg.project_id,current['user_id'],current['auth_version'],task,time.time(),opid,preview_id))
        conn.execute('UPDATE restore_previews SET used_at=? WHERE id=?',(time.time(),preview_id))
        auth.event(conn,current['user_id'],'restore_confirmed','local-web',project=cfg.project_id)
    return jid


def check_job(conn,item):
    row=conn.execute('SELECT * FROM restore_operations WHERE id=? AND project_id=?',(item['restore_op_id'],item['project_id'])).fetchone()
    if not row or row['actor_id']!=item['actor_id'] or row['actor_version']!=item['actor_version']:raise BackupError('restore_access')
    user=auth._lookup(conn,row['session_digest'])
    if not user or user['auth_version']!=item['actor_version'] or not permitted(conn,user,item['project_id']):raise BackupError('restore_access')
    return dict(row)


def update(opid,**values):
    allowed={'state','work_identity','safety_point_id','recovery_point_id','error_code'}
    if set(values)-allowed:raise BackupError('restore_journal')
    with projects.registry() as conn:
        conn.execute('UPDATE restore_operations SET '+','.join(k+'=?' for k in values)+',updated_at=? WHERE id=?',
                     (*values.values(),time.time(),opid))


def _source_check(spec,tick):
    original=spec['source'];kind='snapshot' if original['kind']=='cas' else original['kind']
    fresh=sources.inspect(kind,original['id'],tick)
    if fresh['fingerprint']!=original['fingerprint']:raise BackupError('restore_stale')


def _current_check(cfg,spec,tick):
    target,exists,_=fs.validate_target(cfg,spec['mode'],spec['target'] if spec['mode'] in ('alternate','recovery') else '')
    if str(target)!=spec['target'] or exists!=spec['exists'] or fs.root_id(target.parent)!=spec['parent_id']:raise BackupError('restore_stale')
    actual=fs.state(scoped(cfg,spec),tick,spec['source']['secret_policy']) if exists else dict(root=None,entries={})
    if actual!=spec['current']:raise BackupError('restore_stale')


def _sqlite_check(path,tick):
    # SQLite may canonicalize names internally. Give it a copy in application-owned storage,
    # never a filename underneath a project directory that another user can rename.
    with tempfile.TemporaryDirectory(prefix='restore-sqlite-',dir=settings.temp_dir) as temporary:
        copy=Path(temporary)/'check.sqlite'
        with path.open('rb') as source,copy.open('xb') as dest:
            os.fchmod(dest.fileno(),0o600)
            for chunk in iter(lambda:source.read(CHUNK),b''):tick();dest.write(chunk)
            dest.flush();os.fsync(dest.fileno())
        deadline=time.monotonic()+20
        conn=sqlite3.connect(copy.as_uri()+'?mode=ro&immutable=1',uri=True)
        try:
            def stop():
                tick()
                return int(time.monotonic()>deadline)
            conn.set_progress_handler(stop,1000)
            if conn.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:raise BackupError('sqlite_invalid')
        finally:conn.close()


class Journal:
    def __init__(self,op,tick=lambda:None,progress=lambda **_:None,checkpoint=None):
        self.op=op;self.id=op['id'];self.spec=json.loads(op['spec_json']);self.cfg=projects.current_settings.get()
        self.target=Path(op['target_path']);self.work=Path(op['work_path']);self.tick=tick;self.progress=progress
        self.canonical_work=self.work;self.pin_context=None
        self.checkpoint=checkpoint or tick
        self.root=self.spec['current']['root']
        self.parents={p:[e['dev'],e['ino']] for p,e in self.spec['current']['entries'].items() if e['type']=='dir'}

    def steps(self):
        with projects.registry() as conn:
            return [dict(r,details=json.loads(r['details'])) for r in conn.execute('SELECT * FROM restore_steps WHERE operation_id=? ORDER BY seq',(self.id,))]

    def add(self,kind,path,aux,details):
        self.checkpoint()
        with projects.registry() as conn:
            seq=conn.execute('SELECT coalesce(max(seq),0)+1 FROM restore_steps WHERE operation_id=?',(self.id,)).fetchone()[0]
            conn.execute('INSERT INTO restore_steps(operation_id,seq,kind,path,aux,details) VALUES(?,?,?,?,?,?)',
                         (self.id,seq,kind,path,aux,canonical(details).decode()))
        return seq

    def done(self,seq):
        with projects.registry() as conn:conn.execute('UPDATE restore_steps SET done=1 WHERE operation_id=? AND seq=?',(self.id,seq))

    def guard(self):
        self.checkpoint()
        self.validate_workspace()
        validate_project(self.target,self.cfg)
        if fs.root_id(self.target)!=self.root:raise BackupError('restore_stale')

    def workspace(self):
        owner=self.target if self.spec['exists'] else self.target.parent
        expected=self.spec['current']['root'] if self.spec['exists'] else self.spec['parent_id']
        with open_directory(owner) as parent:
            if [os.fstat(parent).st_dev,os.fstat(parent).st_ino]!=expected:raise BackupError('restore_stale')
            os.mkdir(self.work.name,mode=0o700,dir_fd=parent);os.fsync(parent)
            opened=os.open(self.work.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            st=os.fstat(opened);ids={'work':[st.st_dev,st.st_ino]}
            self.pin(opened,ids['work'])
        finally:os.close(opened)
        update(self.id,work_identity=canonical(ids).decode())
        self.op['work_identity']=canonical(ids).decode()
        marker=canonical(dict(id=self.id,nonce=self.op['nonce']))
        marker_fd=os.open(self.work/'owner.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(marker_fd,'wb') as stream:
            stream.write(marker);stream.flush();os.fsync(stream.fileno())
        for name in ('stage','undo','dirs','reverted'):
            os.mkdir(self.work/name,0o700)
        if not self.spec['exists']:
            os.mkdir(self.work/'tree',0o700);ids['tree']=fs.root_id(self.work/'tree')
        with open_directory(self.work) as fd:os.fsync(fd)
        update(self.id,work_identity=canonical(ids).decode());self.op['work_identity']=canonical(ids).decode()
        return ids

    def pin(self,fd=None,expected=None):
        if self.pin_context:return
        if fd is None:
            ids=json.loads(self.op['work_identity'] or '{}')
            with open_directory(self.canonical_work) as opened:self.pin(opened,ids.get('work'))
            return
        self.pin_context=private_fd(fd,self.canonical_work,expected)
        self.work=self.pin_context.__enter__()

    def close(self):
        if self.pin_context:
            self.pin_context.__exit__(None,None,None);self.pin_context=None;self.work=self.canonical_work

    def validate_workspace(self):
        if not self.op['work_identity']:raise BackupError('restore_workspace')
        ids=json.loads(self.op['work_identity'])
        if fs.root_id(self.canonical_work)!=ids['work']:raise BackupError('restore_workspace')
        with read_private(self.work/'owner.json') as stream:
            if json.loads(stream.read(4096))!=dict(id=self.id,nonce=self.op['nonce']):raise BackupError('restore_workspace')
        return ids

    def safety(self,root,label):
        sid=hashlib.sha256((self.id+label).encode()).hexdigest()[:32]
        update(self.id,**{'safety_point_id' if label=='before' else 'recovery_point_id':sid})
        cfg=replace(self.cfg,agent_root=root,exclusion_rules=tuple(self.spec['rules']))
        token=projects.current_settings.set(cfg)
        try:
            opts=backups.policy(self.cfg.project_id)
            item=backups._create_locked('pre_restore','Pre-Restore ['+self.spec['mode']+'] '+self.spec['target'],self.op['actor_id'],sid,
                                       self.tick,self.progress,options_override=opts,
                                       restore_context=dict(operation_id=self.id,target=str(self.target),existed=bool(self.target.exists())))
            backups.verified_chain(item['point_id'],self.tick)
            with db.db_conn() as conn:conn.execute('UPDATE backup_points SET protected=1 WHERE id=?',(item['point_id'],))
        finally:projects.current_settings.reset(token)
        return item

    def stage(self):
        desired=self.spec['plan']['desired']
        files={p:self.work/'stage'/str(n) for n,(p,e) in enumerate(sorted(desired.items())) if e['type']=='file'}
        sources.stage(self.spec['source'],files,self.tick)
        self.progress(total_files=len(files),total_bytes=sum(desired[p]['size'] for p in files),progress_files=0,progress_bytes=0)
        prepared={}
        for p,path in files.items():
            self.tick();entry=desired[p]
            with path.open('rb') as stream:
                header=stream.read(16);stream.seek(0)
                if digest_stream(stream,self.tick)!=(entry['sha256'],entry['size']):raise BackupError('corrupt')
            suffix=next((s for s in ('-wal','-shm','-journal') if p.endswith(s)),None)
            if suffix:
                base=p[:-len(suffix)]
                related=header[:4] in (b'\x37\x7f\x06\x82',b'\x37\x7f\x06\x83') or bool(desired.get(base,{}).get('sqlite'))
                if base and not base.endswith('/') and self.target.exists() and not (self.target/base).is_dir():
                    from .filesystem import open_project_file
                    try:
                        with open_project_file(self.target,base,self.cfg) as original:
                            related=related or original.read(16)==b'SQLite format 3\0'
                    except FileNotFoundError:pass
                if related:raise BackupError('restore_sqlite_family')
            if entry.get('sqlite'):_sqlite_check(path,self.tick)
            os.chmod(path,entry['mode']);os.utime(path,ns=(entry['mtime_ns'],entry['mtime_ns']))
            with path.open('rb') as stream:os.fsync(stream.fileno())
            prepared[p]=dict(aux=path.name,node={**fs.node(path.stat()),'sha256':entry['sha256']})
        for n,p in enumerate(self.spec['plan']['make']):
            path=self.work/'dirs'/str(n);os.mkdir(path,0o700)
            prepared[p]=dict(aux=str(n),node=fs.node(path.stat()))
        for name in ('stage','dirs'):
            with open_directory(self.work/name) as fd:os.fsync(fd)
        return prepared

    def move_out(self,path,before):
        self.guard();actual=fs.actual(self.target,path,self.root,self.tick)
        if not fs.same(actual,before,metadata=before['type']=='file') or actual['mode']!=before['mode']:raise BackupError('restore_stale')
        seq=self.add('move',path,'',{'before':before})
        with fs.parent_fd(self.target,path,self.root,self.parents) as (parent,name),open_directory(self.work/'undo') as undo:
            if before['type']=='dir':
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                try:
                    if os.listdir(child):raise BackupError('restore_scope')
                finally:os.close(child)
            fs.noreplace(parent,name,undo,str(seq))
        moved=fs.actual(self.work/'undo',str(seq),fs.root_id(self.work/'undo'),self.tick)
        if not fs.same(moved,before):raise BackupError('restore_stale')
        if before['type']=='dir':
            with open_directory(self.work/'undo'/str(seq)) as moved_dir:
                if os.listdir(moved_dir):raise BackupError('restore_conflict')
        self.done(seq)
        if before['type']=='dir':self.parents.pop(path,None)

    def install(self,path,prepared,kind):
        self.guard()
        seq=self.add(kind,path,prepared['aux'],{'new':prepared['node']})
        with open_directory(self.work/('dirs' if kind=='mkdir' else 'stage')) as source,fs.parent_fd(self.target,path,self.root,self.parents) as (parent,name):
            fs.noreplace(source,prepared['aux'],parent,name)
        if kind=='mkdir':self.parents[path]=[prepared['node']['dev'],prepared['node']['ino']]
        if not fs.same(fs.actual(self.target,path,self.root,self.tick),prepared['node']):raise BackupError('restore_stale')
        self.done(seq)

    def metadata(self,path,entry):
        self.guard()
        with open_directory(self.target/path) as fd:
            st=os.fstat(fd)
            if [st.st_dev,st.st_ino]!=self.parents.get(path):raise BackupError('restore_stale')
            seq=self.add('metadata',path,'',{'before':fs.node(st),'new':dict(mode=entry['mode'],mtime_ns=entry['mtime_ns'])})
            os.fchmod(fd,entry['mode']);os.utime(fd,ns=(entry['mtime_ns'],entry['mtime_ns']));os.fsync(fd)
        self.done(seq)

    def apply(self,prepared):
        if not self.spec['exists']:
            # Publish a fully staged new tree in one no-clobber directory rename.
            tree=self.work/'tree'
            for path,e in sorted(self.spec['plan']['desired'].items(),key=lambda x:(x[0].count('/'),x[0])):
                self.tick();dest=tree/path
                if e['type']=='dir':dest.mkdir(mode=0o700)
                else:
                    dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                    os.rename(self.work/'stage'/prepared[path]['aux'],dest)
            for path,e in sorted(self.spec['plan']['desired'].items(),key=lambda x:x[0].count('/'),reverse=True):
                if e['type']=='dir':
                    os.chmod(tree/path,e['mode']);os.utime(tree/path,ns=(e['mtime_ns'],e['mtime_ns']))
                with (open_directory(tree/path) if e['type']=='dir' else (tree/path).open('rb')) as handle:
                    os.fsync(handle if isinstance(handle,int) else handle.fileno())
            ids=json.loads(self.op['work_identity'])
            with open_directory(tree) as fd:os.fsync(fd)
            seq=self.add('publish','',self.target.name,dict(new_root=ids['tree']))
            with open_directory(self.work) as source,open_directory(self.target.parent) as parent:
                if [os.fstat(parent).st_dev,os.fstat(parent).st_ino]!=self.spec['parent_id']:raise BackupError('restore_stale')
                fs.noreplace(source,'tree',parent,self.target.name)
            self.root=ids['tree'];self.done(seq)
            return
        for path in self.spec['plan']['remove']:self.move_out(path,self.spec['plan']['before'][path])
        for path in self.spec['plan']['make']:self.install(path,prepared[path],'mkdir')
        files=0;size=0
        for path in self.spec['plan']['install']:
            self.install(path,prepared[path],'install');files+=1;size+=self.spec['plan']['desired'][path]['size']
            self.progress(progress_files=files,progress_bytes=size)
        for path,e in sorted(self.spec['plan']['desired'].items(),key=lambda x:x[0].count('/'),reverse=True):
            if e['type']=='dir':self.metadata(path,e)

    def verify_result(self):
        self.guard()
        cfg=scoped(self.cfg,self.spec)
        current=fs.state(cfg,self.tick,self.spec['source']['secret_policy'])
        desired=self.spec['plan']['desired']
        for p,e in desired.items():
            actual=current['entries'].get(p)
            if not actual or any(actual.get(k)!=e.get(k) for k in (('type','mode','mtime_ns','size','sha256') if e['type']=='file' else ('type','mode','mtime_ns'))):
                raise BackupError('restore_verify')
        if self.spec['mode']!='files' and set(current['entries'])!=set(desired):raise BackupError('restore_verify')

    def cleanup(self):
        if not self.op['work_identity']:return
        ids=self.validate_workspace()
        fs.remove_private_tree(self.canonical_work,ids['work'])


def execute(opid,tick=lambda:None,progress=lambda **_:None,commit_check=None):
    cfg=projects.current_settings.get();op=operation(opid);journal=Journal(op,tick,progress,commit_check);applying=False
    with project_lock(cfg.project_id,restore_id=opid),capacity():
        try:
            if op['state']!='queued':raise BackupError('restore_preview')
            tick()
            if journal.spec['binding']!=binding(cfg):raise BackupError('restore_stale')
            _current_check(cfg,journal.spec,tick);_source_check(journal.spec,tick)
            _space(journal.target,journal.spec['exists'],journal.spec['source'],journal.spec['plan'])
            active=fs.processes(journal.target) if journal.spec['exists'] else dict(pids=[])
            if active['pids']:raise BackupError('restore_process')
            update(opid,state='preparing');journal.workspace()
            safety=journal.safety(journal.target if journal.spec['exists'] else journal.work/'tree','before')
            # Every overwritten regular file is represented in insurance (SQLite sidecars fold into DB).
            insured={e['path']:e for e in safety['manifest']['files']}
            for path in journal.spec['plan']['remove']:
                before=journal.spec['plan']['before'][path]
                if before['type']=='file' and path not in journal.spec['plan']['sidecars']:
                    entry=insured.get(path)
                    if not entry or not (entry.get('sqlite') or entry.get('sha256')==before['sha256']):raise BackupError('restore_safety')
            for sidecar in journal.spec['plan']['sidecars']:
                base=next((p for p in insured if any(sidecar==p+suffix for suffix in ('-wal','-shm','-journal'))),None)
                if base is None or not insured[base].get('sqlite'):raise BackupError('restore_safety')
            prepared=journal.stage()
            _current_check(cfg,journal.spec,tick)
            if fs.processes(journal.target)['pids'] if journal.spec['exists'] else False:raise BackupError('restore_process')
            backups.verified_chain(safety['point_id'],tick)
            (commit_check or tick)()
            update(opid,state='applying');applying=True
            journal.apply(prepared);journal.verify_result()
            update(opid,state='committed')
            # Undo originals stay private and excluded. Never erase a late writer's old inode.
        except Exception:
            # No automatic rollback of user files. Keep durable undo and insurance after apply starts.
            if applying:
                update(opid,state='interrupted',error_code='restore_interrupted')
                raise BackupError('restore_interrupted') from None
            try:journal.cleanup()
            except (OSError,ValueError):pass
            settle(opid,'failed','restore_failed')
            raise
        finally:journal.close()
    return opid


def settle(opid,state,error=''):
    with projects.registry() as conn:
        conn.execute('BEGIN IMMEDIATE')
        row=conn.execute('SELECT spec_json FROM restore_operations WHERE id=?',(opid,)).fetchone()
        conn.execute('UPDATE restore_operations SET state=?,error_code=?,updated_at=? WHERE id=?',(state,error,time.time(),opid))
        predecessor=json.loads(row[0]).get('recovery_of')
        if predecessor and state in ('failed','rolled_back'):
            conn.execute("UPDATE restore_operations SET state='interrupted',updated_at=? WHERE id=? AND state='superseded'",(time.time(),predecessor))


def _undo_check(journal,tick):
    spec=journal.spec
    if spec['binding']!=binding(journal.cfg):raise BackupError('restore_stale')
    target=journal.target
    original=spec['current']['root'];steps=journal.steps()
    exists=target.exists()
    if target.is_symlink():raise BackupError('unsafe_path')
    if original:
        validate_project(target,journal.cfg)
        if fs.root_id(target)!=original:raise BackupError('restore_stale')
    elif exists:
        ids=json.loads(journal.op['work_identity'] or '{}')
        if fs.root_id(target)!=ids.get('tree'):raise BackupError('restore_conflict')
        journal.root=ids['tree']
    if steps:
        journal.validate_workspace()
        if not journal.op['safety_point_id']:raise BackupError('restore_safety')
        backups.verified_chain(journal.op['safety_point_id'],tick)
    current=fs.state(scoped(journal.cfg,spec),tick,spec['source']['secret_policy']) if exists else dict(root=None,entries={})
    virtual={p:dict(e) for p,e in current['entries'].items()}
    for step in reversed(steps):
        if step['undone']:continue
        tick();d=step['details'];path=step['path']
        if step['kind']=='publish':
            if exists:
                desired=spec['plan']['desired']
                if set(virtual)!=set(desired) or any(e.get('sha256')!=virtual[p].get('sha256') for p,e in desired.items() if e['type']=='file'):
                    raise BackupError('restore_conflict')
                virtual={}
            continue
        value=virtual.get(path)
        if step['kind'] in ('install','mkdir'):
            if value is None:continue
            if not fs.same(value,d['new'],metadata=step['kind']=='install'):raise BackupError('restore_conflict')
            if step['kind']=='mkdir' and any(p.startswith(path+'/') for p in virtual):raise BackupError('restore_conflict')
            del virtual[path]
        elif step['kind']=='move':
            undo=fs.actual(journal.work/'undo',str(step['seq']),fs.root_id(journal.work/'undo'),tick)
            if undo:
                if not fs.same(undo,d['before']) or value is not None:raise BackupError('restore_conflict')
                if undo['type']=='dir':
                    with open_directory(journal.work/'undo'/str(step['seq'])) as fd:
                        if os.listdir(fd):raise BackupError('restore_conflict')
                virtual[path]=undo
            elif not fs.same(value,d['before']):raise BackupError('restore_conflict')
        elif step['kind']=='metadata':
            if not value or [value['dev'],value['ino']]!=[d['before']['dev'],d['before']['ino']]:raise BackupError('restore_conflict')
            if value['mode'] not in (d['before']['mode'],d['new']['mode'],0o700):raise BackupError('restore_conflict')
    return current


def recovery_preview(user,raw,opid,method='undo'):
    op=operation(opid)
    if op['state']!='interrupted':raise BackupError('restore_preview')
    with projects.registry() as conn:actor(conn,user['digest'],settings.project_id)
    if method=='insurance':
        if not op['safety_point_id']:raise BackupError('restore_safety')
        return preview(user,raw,'point',op['safety_point_id'],'recovery',op['target_path'],recovery_of=opid)
    if method!='undo':raise BackupError('restore_mode')
    cfg=projects.current_settings.get()
    with project_lock(cfg.project_id,restore_id=opid),capacity():
        journal=Journal(op)
        try:
            if op['work_identity']:journal.pin()
            current=_undo_check(journal,lambda:None)
            touched={s['path'] for s in journal.steps()}
            if not journal.spec['exists']:touched=set(current['entries'])
            changes=[]
            for path in sorted(touched):
                if not path:continue
                before=journal.spec['current']['entries'].get(path);now=current['entries'].get(path)
                if before is None and now is None:continue
                changes.append(dict(path=path,change='deleted' if before is None else ('added' if now is None else 'modified'),
                                    type=(before or now)['type'],size=(before or now).get('size',0)))
            spec=dict(action='undo',operation_id=opid,target=op['target_path'],binding=binding(cfg),
                      current=current,plan=dict(changes=changes),processes=fs.processes(journal.target) if current['root'] else dict(pids=[],complete=True))
            return save_preview(user,raw,spec)
        finally:journal.close()


def execute_undo(opid,preview_id,tick=lambda:None,progress=lambda **_:None,commit_check=None):
    cfg=projects.current_settings.get();op=operation(opid);journal=Journal(op,tick,progress,commit_check)
    if op['state']!='undoing':raise BackupError('restore_preview')
    with project_lock(cfg.project_id,restore_id=opid),capacity():
        try:
            if op['work_identity']:journal.pin()
            with projects.registry() as conn:
                row=conn.execute('SELECT spec_json FROM restore_previews WHERE id=? AND project_id=?',(preview_id,cfg.project_id)).fetchone()
            if not row:raise BackupError('restore_preview')
            shown=json.loads(row[0]);current=_undo_check(journal,tick)
            if current!=shown['current']:raise BackupError('restore_stale')
            if fs.processes(journal.target)['pids'] if current['root'] else False:raise BackupError('restore_process')
            tick()
            # New insurance preserves the partial state before undo overwrites it.
            if current['root']:
                insured=journal.safety(journal.target,'undo:'+preview_id)
                bypath={e['path']:e for e in insured['manifest']['files']}
                recorded=journal.steps()
                touched=set(current['entries']) if any(s['kind']=='publish' for s in recorded) else {s['path'] for s in recorded}
                for path in touched:
                    value=current['entries'].get(path)
                    if value and value['type']=='file':
                        entry=bypath.get(path)
                        if not entry or not (entry.get('sqlite') or entry.get('sha256')==value['sha256']):raise BackupError('restore_safety')
            (commit_check or tick)()
            steps=journal.steps()
            for step in steps:
                if step['kind']=='mkdir' and not step['undone']:
                    d=step['details']['new'];journal.parents[step['path']]=[d['dev'],d['ino']]
            for step in reversed(steps):
                tick()
                if step['undone']:continue
                path=step['path'];d=step['details'];kind=step['kind']
                if kind=='publish':
                    if journal.target.exists():
                        ids=json.loads(op['work_identity']);journal.root=ids['tree']
                        with open_directory(journal.target.parent) as parent,open_directory(journal.work) as work:
                            if fs.root_id(journal.target)!=ids['tree']:raise BackupError('restore_conflict')
                            fs.noreplace(parent,journal.target.name,work,'tree')
                elif kind=='metadata':
                    with open_directory(journal.target/path) as fd:
                        if [os.fstat(fd).st_dev,os.fstat(fd).st_ino]!=[d['before']['dev'],d['before']['ino']]:raise BackupError('restore_conflict')
                        os.fchmod(fd,0o700);os.fsync(fd)
                elif kind in ('install','mkdir'):
                    journal.guard()
                    actual=fs.actual(journal.target,path,journal.root,tick)
                    if actual:
                        if not fs.same(actual,d['new'],metadata=kind=='install'):raise BackupError('restore_conflict')
                        with fs.parent_fd(journal.target,path,journal.root,journal.parents) as (parent,name):
                            if kind=='mkdir':os.rmdir(name,dir_fd=parent)
                            else:
                                with open_directory(journal.work/'reverted') as reverted:
                                    fs.noreplace(parent,name,reverted,str(step['seq']))
                            os.fsync(parent)
                    if kind=='mkdir':journal.parents.pop(path,None)
                elif kind=='move':
                    journal.guard()
                    with open_directory(journal.work/'undo') as undo:
                        saved=fs.actual(journal.work/'undo',str(step['seq']),fs.root_id(journal.work/'undo'),tick)
                        if saved:
                            if not fs.same(saved,d['before']):raise BackupError('restore_conflict')
                            with fs.parent_fd(journal.target,path,journal.root,journal.parents) as (parent,name):
                                fs.noreplace(undo,str(step['seq']),parent,name)
                            if d['before']['type']=='dir':journal.parents[path]=[d['before']['dev'],d['before']['ino']]
                with projects.registry() as conn:conn.execute('UPDATE restore_steps SET undone=1 WHERE operation_id=? AND seq=?',(opid,step['seq']))
            if journal.spec['exists']:
                # Restore original directory metadata last, after child moves alter mtimes.
                for path,e in sorted(journal.spec['current']['entries'].items(),key=lambda x:x[0].count('/'),reverse=True):
                    if e['type']=='dir' and path in {s['path'] for s in steps}:
                        with open_directory(journal.target/path) as fd:
                            if [os.fstat(fd).st_dev,os.fstat(fd).st_ino]!=[e['dev'],e['ino']]:raise BackupError('restore_conflict')
                            os.fchmod(fd,e['mode']);os.utime(fd,ns=(e['mtime_ns'],e['mtime_ns']));os.fsync(fd)
                for path,e in journal.spec['current']['entries'].items():
                    if not fs.same(fs.actual(journal.target,path,journal.root,tick),e):raise BackupError('restore_verify')
            elif journal.target.exists():raise BackupError('restore_verify')
            settle(opid,'rolled_back')
            # Keep reverted installed inodes as well as insurance. Cleanup requires later review.
        except Exception:
            update(opid,state='interrupted',error_code='restore_interrupted')
            raise BackupError('restore_interrupted') from None
        finally:journal.close()
    return opid


def reconcile(jid,opid,undo=False):
    """Restart changes journal state only. Never performs a source mutation."""
    op=operation(opid)
    successful=op['state']==('rolled_back' if undo else 'committed')
    if op['state'] in ('queued','preparing','applying','undoing'):
        update(opid,state='interrupted',error_code='restore_interrupted')
    return successful
