"""Owner-confirmed deletion with durable retry journals and canonical storage boundaries."""
from pathlib import Path
import hashlib,hmac,json,os,secrets,shutil,stat,time
from . import projects,auth,db,backups,i18n
from .backup_storage import project_lock,private_dir,read_private,BackupError
from .filesystem import open_directory,inside
from .maintenance import atomic_json


class Dependencies(ValueError):
    def __init__(self,ids):
        self.ids=ids
        super().__init__('delete.dependencies')


def identity(project,archive=None):
    return hashlib.sha256(json.dumps([project,archive],sort_keys=True,default=str).encode()).hexdigest()


def journal_path(pid,aid=None):
    return private_dir(projects.base_settings.data_dir/'deletions')/(str(pid)+('-archive-'+str(aid) if aid is not None else '-project')+'.json')


def pending(pid):
    path=journal_path(pid)
    return path.exists() and json.loads(path.read_text())['phase']!='complete'


def issue(user,project,archive=None):
    token=secrets.token_hex(32)
    folder=private_dir(projects.base_settings.temp_dir/'delete-confirmations')
    atomic_json(folder/token,dict(session=user['digest'],identity=identity(project,archive),expires=time.time()+600))
    return token


def consume(token,user,project,archive=None):
    if len(token)!=64 or any(c not in '0123456789abcdef' for c in token):raise ValueError('delete.confirm_error')
    folder=private_dir(projects.base_settings.temp_dir/'delete-confirmations')
    try:
        with read_private(folder/token) as stream:value=json.load(stream)
        if value['expires']<time.time() or not hmac.compare_digest(value['session'],user['digest']) or value['identity']!=identity(project,archive):raise ValueError('delete.confirm_error')
        with open_directory(folder) as fd:os.unlink(token,dir_fd=fd);os.fsync(fd)
    except FileNotFoundError:raise ValueError('delete.confirm_error') from None


def idle(conn,pid,queued=False):
    states="('running')" if queued else "('queued','running')"
    if conn.execute('SELECT 1 FROM jobs WHERE project_id=? AND state IN '+states,(pid,)).fetchone():raise ValueError('delete.busy')
    if conn.execute("SELECT 1 FROM restore_operations WHERE project_id=? AND state IN ('queued','preparing','applying','interrupted','undoing')",(pid,)).fetchone():raise ValueError('delete.busy')


def administrator(conn,user):
    fresh=auth._lookup(conn,user['digest'])
    if not fresh or fresh['role']!='administrator':raise ValueError('delete.access')


def project_paths(project):
    cfg=projects.base_settings;pid=project['id']
    paths=[(root/'projects',str(pid)) for root in (cfg.data_dir,cfg.backups_dir,cfg.metadata_dir,cfg.reports_dir,cfg.content_dir)]
    expected=[cfg.data_dir/'projects'/str(pid)/'history.sqlite',cfg.backups_dir/'projects'/str(pid),cfg.reports_dir/'projects'/str(pid)]
    for key,wanted in zip(('history_path','backup_path','report_path'),expected):
        if project[key] and Path(project[key])!=wanted:raise ValueError('delete.storage')
    for parent,name in paths:
        target=parent/name
        if inside(Path(project['path']),target) or inside(target,Path(project['path'])):raise ValueError('delete.storage')
        if parent.exists():
            with open_directory(parent) as fd:
                try:entry=os.stat(name,dir_fd=fd,follow_symlinks=False)
                except FileNotFoundError:continue
                if not stat.S_ISDIR(entry.st_mode) or entry.st_uid!=os.geteuid():raise ValueError('delete.storage')
    return paths


def delete_project(pid,user,token,confirmation):
    with project_lock(pid),projects.registry() as conn:
        conn.execute('BEGIN IMMEDIATE');administrator(conn,user)
        row=conn.execute('SELECT * FROM projects WHERE id=?',(pid,)).fetchone()
        if not row:raise ValueError('delete.missing')
        project=projects.decode(row)
        if project['enabled']:raise ValueError('delete.active')
        if confirmation!=project['name']:raise ValueError('delete.confirm_error')
        idle(conn,pid,queued=True);paths=project_paths(project)
        for other in conn.execute('SELECT id,path,history_path,backup_path,report_path FROM projects WHERE id!=?',(pid,)):
            for value in (other['path'],other['history_path'],other['backup_path'],other['report_path']):
                if value and any(inside(Path(value),parent/name) or inside(parent/name,Path(value)) for parent,name in paths):raise ValueError('delete.storage')
        from . import restore_fs
        journal=journal_path(pid)
        previous=json.loads(journal.read_text()).get('workspaces',[]) if journal.exists() else []
        workspaces=[]
        for operation in conn.execute('SELECT * FROM restore_operations WHERE project_id=?',(pid,)):
            work=Path(operation['work_path'])
            if not os.path.lexists(work):continue
            spec=json.loads(operation['spec_json']);target=Path(operation['target_path'])
            if spec['target']!=str(target) or work!=(target if spec['exists'] else target.parent)/(restore_fs.WORK_PREFIX+operation['id']):raise ValueError('delete.storage')
            expected=json.loads(operation['work_identity'])['work']
            if restore_fs.root_id(work)!=expected:raise ValueError('delete.storage')
            descriptor=dict(path=str(work),identity=expected,operation_id=operation['id'],nonce=operation['nonce'])
            try:
                with read_private(work/'owner.json') as stream:marker=json.load(stream)
                if marker!=dict(id=operation['id'],nonce=operation['nonce']):raise ValueError('delete.storage')
            except FileNotFoundError:
                if descriptor not in previous:raise ValueError('delete.storage') from None
            workspaces.append(descriptor)
        consume(token,user,project)
        atomic_json(journal,dict(phase='deleting',project_id=pid,paths=[str(parent/name) for parent,name in paths],workspaces=workspaces))
        for workspace in workspaces:restore_fs.remove_private_tree(Path(workspace['path']),workspace['identity'])
        for parent,name in paths:
            if not parent.exists():continue
            with open_directory(parent) as fd:
                try:shutil.rmtree(name,dir_fd=fd)
                except FileNotFoundError:pass
                os.fsync(fd)
        conn.execute('DELETE FROM restore_steps WHERE operation_id IN (SELECT id FROM restore_operations WHERE project_id=?)',(pid,))
        conn.execute('DELETE FROM jobs WHERE project_id=?',(pid,))
        for table in ('restore_operations','restore_previews','job_schedules','backup_policies','project_access'):
            conn.execute('DELETE FROM '+table+' WHERE project_id=?',(pid,))
        conn.execute('DELETE FROM projects WHERE id=?',(pid,))
        auth.event(conn,user['user_id'],'project_deleted','web',project=pid)
        conn.commit();atomic_json(journal,dict(phase='complete',project_id=pid))


def archive_row(aid):
    with db.db_conn() as conn:
        row=conn.execute('SELECT b.*,p.id AS point_id,p.kind,p.parent_id,p.key_id,p.protected,p.state,p.snapshot_id AS point_snapshot_id FROM backups b LEFT JOIN backup_points p ON p.backup_id=b.id WHERE b.id=?',(aid,)).fetchone()
    if not row:raise ValueError('delete.missing')
    return dict(row)


def delete_archive(pid,aid,user,token,confirmation):
    from .config import settings
    if pid!=settings.project_id:raise ValueError('delete.access')
    if settings.backups_dir!=projects.base_settings.backups_dir/'projects'/str(pid):raise ValueError('delete.storage')
    with project_lock(pid),projects.registry() as registry:
        registry.execute('BEGIN IMMEDIATE');administrator(registry,user);idle(registry,pid)
        project=projects.get_project(pid);archive=archive_row(aid)
        if confirmation!=str(aid):raise ValueError('delete.confirm_error')
        if archive['protected']:raise ValueError('delete.protected')
        point=archive['point_id']
        if point:
            with db.db_conn() as conn:
                children=[str(r[0]) for r in conn.execute('SELECT backup_id FROM backup_points WHERE parent_id=? ORDER BY backup_id',(point,))]
            if children:raise Dependencies(', '.join(children))
            for row in registry.execute('SELECT spec_json,safety_point_id,recovery_point_id FROM restore_operations WHERE project_id=?',(pid,)):
                if any(point in str(value) for value in row):raise ValueError('delete.referenced')
            for row in registry.execute('SELECT spec_json FROM restore_previews WHERE project_id=? AND expires_at>? AND used_at IS NULL',(pid,time.time())):
                if point in row[0]:raise ValueError('delete.referenced')
        path=Path(archive['archive_path'])
        if not path.is_relative_to(settings.backups_dir) or '..' in path.parts:raise ValueError('delete.storage')
        with open_directory(path.parent) as fd:
            try:entry=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:entry=None
            if entry and (not stat.S_ISREG(entry.st_mode) or entry.st_uid!=os.geteuid()):raise ValueError('delete.storage')
        consume(token,user,project,archive)
        journal=journal_path(pid,aid);atomic_json(journal,dict(phase='deleting',project_id=pid,archive_id=aid,path=str(path)))
        if point:
            with db.db_conn() as conn:
                conn.execute("UPDATE backup_points SET state='deleting' WHERE id=?",(point,))
                conn.execute("UPDATE snapshots SET content_status='unavailable' WHERE backup_point_id=?",(point,))
            point_data=dict(archive,id=point,snapshot_id=archive['point_snapshot_id'])
            backups.finish_deletion(point_data)
        else:
            with open_directory(path.parent) as fd:
                try:os.unlink(path.name,dir_fd=fd)
                except FileNotFoundError:pass
                os.fsync(fd)
        with db.db_conn() as conn:
            conn.execute('BEGIN IMMEDIATE')
            if point:
                conn.execute('DELETE FROM backup_point_objects WHERE point_id=?',(point,))
                conn.execute('DELETE FROM backup_points WHERE id=?',(point,))
            conn.execute('DELETE FROM backups WHERE id=?',(aid,))
        auth.event(registry,user['user_id'],'backup_deleted','web',project=pid,target=aid)
        registry.commit();atomic_json(journal,dict(phase='complete',project_id=pid,archive_id=aid))
