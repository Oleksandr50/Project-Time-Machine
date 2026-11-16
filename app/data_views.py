"""Bounded log windows and read-only SQLite inspection on private coherent copies."""
from contextlib import closing
from pathlib import Path
import os
import re
import sqlite3
import tempfile
import time
from .config import settings
from . import scanner
from .redaction import redact,cell,SENSITIVE
from .backup_capture import identity
from .backup_storage import private_dir,ensure_space

LOG_BYTES=2*1024*1024
SQLITE_BYTES=64*1024*1024
RESULT_BYTES=128*1024
LEVELS=('DEBUG','INFO','WARNING','ERROR','CRITICAL')


def permitted_path(value,extensions):
    path=Path(value)
    if not path.is_absolute():path=settings.agent_root/path
    if '..' in path.parts or '\\' in str(path) or '\x00' in str(path):raise ValueError('inspection.path')
    try:rel=path.relative_to(settings.agent_root).as_posix()
    except ValueError:raise ValueError('inspection.path') from None
    from .restore_state import workspaces
    if path.suffix.lower() not in extensions or scanner.excluded(rel) or any(path==Path(w) or Path(w) in path.parents for w in workspaces(settings.project_id)):
        raise ValueError('inspection.path')
    from .analyzer import is_secret_path
    if is_secret_path(rel):raise ValueError('inspection.secret')
    with scanner.open_source(path):pass  # nofollow and root checks at every read, not resolve-then-open
    return path


def log_window(path,lines=200,query='',level=''):
    if not 1<=lines<=2000 or level not in ('',*LEVELS) or len(query)>300:raise ValueError('error.validation')
    path=permitted_path(path,{'.log'})
    with scanner.open_source(path) as stream:
        before=os.fstat(stream.fileno());offset=max(0,before.st_size-LOG_BYTES)
        stream.seek(offset);data=stream.read(LOG_BYTES)
        if offset:
            # Do not display a partial first line, which could omit a secret's field label.
            pos=data.find(b'\n');data=data[pos+1:] if pos>=0 else b''
        after=os.fstat(stream.fileno())
    text=redact(data.decode('utf-8',errors='replace'))
    # A window can start inside a PEM block: opaque long base64 lines are not displayed.
    text=re.sub(r'(?m)^[A-Za-z0-9+/=]{64,}\r?$','[REDACTED]',text)
    rows=text.splitlines();matched=[]
    for line in rows:
        if query and query.casefold() not in line.casefold():continue
        if level and not re.search(r'\b'+('(?:WARNING|WARN)' if level=='WARNING' else '(?:CRITICAL|FATAL)' if level=='CRITICAL' else level)+r'\b',line,re.I):continue
        matched.append(line)
    return dict(content='\n'.join(matched[-lines:]),size=before.st_size,mtime=before.st_mtime,
                truncated=offset>0 or len(matched)>lines,changed=identity(before)!=identity(after),scanned=len(rows),matches=len(matched))


def _quote(name):return '"'+name.replace('"','""')+'"'


def sqlite_inspect(path,table=None,page=1,per_page=25):
    if not 1<=page<=100000 or per_page not in (10,25,50,100):raise ValueError('error.validation')
    path=permitted_path(path,{'.db','.sqlite','.sqlite3'})
    deadline=time.monotonic()+5
    def tick():
        if time.monotonic()>deadline:raise ValueError('inspection.timeout')
    private_dir(settings.temp_dir)
    with tempfile.TemporaryDirectory(prefix='sqlite-view-',dir=settings.temp_dir) as raw:
        work=Path(raw);states={};remaining=SQLITE_BYTES
        for suffix in ('','-wal','-journal'):
            source=Path(str(path)+suffix);dest=work/('capture.sqlite'+suffix)
            try:
                with scanner.open_source(source) as stream:
                    before=os.fstat(stream.fileno());states[suffix]=before
                    if before.st_size>remaining:raise ValueError('inspection.size')
                    ensure_space(work,before.st_size*3)
                    with dest.open('xb') as out:
                        dest.chmod(0o600)
                        while True:
                            tick();chunk=stream.read(min(1024*1024,remaining+1))
                            if not chunk:break
                            remaining-=len(chunk)
                            if remaining<0:raise ValueError('inspection.size')
                            out.write(chunk)
                    if identity(before)!=identity(os.fstat(stream.fileno())):raise ValueError('inspection.changed')
            except FileNotFoundError:
                if not suffix:raise
                states[suffix]=None
        for suffix,before in states.items():
            try:
                with scanner.open_source(Path(str(path)+suffix)) as stream:after=os.fstat(stream.fileno())
            except FileNotFoundError:after=None
            if (before is None)!=(after is None) or before is not None and identity(before)!=identity(after):raise ValueError('inspection.changed')
        normalized=work/'readonly.sqlite'
        try:
            with closing(sqlite3.connect(work/'capture.sqlite',timeout=0.1)) as src,closing(sqlite3.connect(normalized,timeout=0.1)) as dest:
                src.execute('PRAGMA trusted_schema=OFF');src.enable_load_extension(False)
                src.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
                if src.execute('PRAGMA quick_check').fetchall()!=[('ok',)]:raise ValueError('inspection.sqlite')
                src.backup(dest,pages=128,progress=lambda *_:tick(),sleep=0.01)
            normalized.chmod(0o600)
            with closing(sqlite3.connect(normalized.as_uri()+'?mode=ro&immutable=1',uri=True,timeout=0.1)) as conn:
                conn.execute('PRAGMA trusted_schema=OFF');conn.execute('PRAGMA query_only=ON');conn.enable_load_extension(False)
                conn.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
                entries=conn.execute('PRAGMA table_list').fetchmany(102)
                if len(entries)>101:raise ValueError('inspection.tables')
                names=sorted(r[1] for r in entries if r[0]=='main' and r[2]=='table' and not r[1].startswith('sqlite_'))
                if any(len(n)>512 for n in names):raise ValueError('inspection.tables')
                tables=[]
                for name in names:
                    tick();count=conn.execute('SELECT count(*) FROM '+_quote(name)).fetchone()[0]
                    tables.append(dict(name=name,rows=count))
                info=dict(path=str(path),size=states[''].st_size,mtime=states[''].st_mtime,tables=tables,columns=[],rows=[],page=page,per_page=per_page,pages=1,total=0,truncated=False)
                if table is None:return info
                if table not in names:raise ValueError('inspection.table')
                columns=[r[1] for r in conn.execute('PRAGMA table_xinfo('+_quote(table)+')') if r[6]==0]
                if not columns or len(columns)>100 or any(len(c)>512 for c in columns):raise ValueError('inspection.columns')
                # SQL is generated entirely here. Views, virtual/shadow and generated columns are excluded.
                def authorize(action,*_):
                    return sqlite3.SQLITE_OK if action in (sqlite3.SQLITE_SELECT,sqlite3.SQLITE_READ,sqlite3.SQLITE_FUNCTION) else sqlite3.SQLITE_DENY
                conn.set_authorizer(authorize)
                total=next(x['rows'] for x in tables if x['name']==table);pages=max(1,(total+per_page-1)//per_page);page=min(page,pages)
                expressions=["CASE WHEN typeof("+_quote(c)+")='blob' THEN '[BLOB]' ELSE substr(CAST("+_quote(c)+" AS TEXT),1,4096) END" for c in columns]
                cursor=conn.execute('SELECT '+','.join(expressions)+' FROM '+_quote(table)+' LIMIT ? OFFSET ?',(per_page,(page-1)*per_page))
                rows=[];size=0
                for row in cursor:
                    tick()
                    sensitive=SENSITIVE.search(table) or any(c.casefold() in ('key','name','setting','parameter') and isinstance(v,str) and SENSITIVE.search(v) for c,v in zip(columns,row))
                    safe=['[REDACTED]' if sensitive else cell(c,v) for c,v in zip(columns,row)]
                    size+=sum(len(v.encode('utf-8')) for v in safe)
                    if size>RESULT_BYTES:info['truncated']=True;break
                    rows.append(safe)
                info.update(columns=columns,rows=rows,total=total,pages=pages,page=page,table=table)
                return info
        except sqlite3.Error:
            raise ValueError('inspection.sqlite') from None
