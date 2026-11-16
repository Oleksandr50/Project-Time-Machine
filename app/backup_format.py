"""PTM v1 portable ZIP_STORED packages. Strict verification; never extractall."""
from contextlib import contextmanager
import hashlib
import io
import json
import os
import re
import stat
import zipfile
from .backup_storage import (BackupError,CHUNK,read_private,digest_stream,relative_name,
                             consume,object_aad,load_key)

MAX_MANIFEST=16*1024*1024
MAX_ENTRIES=100002


def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def no_duplicates(items):
    result={}
    for key,value in items:
        if key in result:raise BackupError('corrupt')
        result[key]=value
    return result


def json_load(data):
    try:return json.loads(data,object_pairs_hook=no_duplicates)
    except (ValueError,UnicodeError):raise BackupError('corrupt') from None


def validate_manifest(m):
    try:
        if m['format']!='ptm-backup' or m['version']!=1 or not re.fullmatch('[0-9a-f]{32}',m['id']):
            raise BackupError('format')
        if type(m['project_id']) is not int or m['project_id']<1:raise BackupError('corrupt')
        if m['kind'] not in ('full','incremental','checkpoint','pre_restore'):raise BackupError('corrupt')
        if (m['kind']=='incremental')!=(m['parent'] is not None):raise BackupError('corrupt')
        if m['parent'] and (set(m['parent'])!={'id','archive_sha256','manifest_sha256'} or
            not re.fullmatch('[0-9a-f]{32}',m['parent']['id']) or any(not re.fullmatch('[0-9a-f]{64}',m['parent'][k]) for k in ('archive_sha256','manifest_sha256'))):
            raise BackupError('corrupt')
        if not isinstance(m['files'],list) or len(m['files'])>100000:raise BackupError('format')
        names=set();folded=set();file_names=set();objects={}
        for entry in m['files']:
            name=relative_name(entry['path'])
            if name in names or name.casefold() in folded:raise BackupError('unsafe_path')
            names.add(name);folded.add(name.casefold())
            if entry['type'] not in ('file','dir'):raise BackupError('corrupt')
            if type(entry['mode']) is not int or entry['mode']&~0o777:raise BackupError('corrupt')
            if type(entry['mtime_ns']) is not int:raise BackupError('corrupt')
            if entry['type']=='file':
                file_names.add(name)
                if type(entry['size']) is not int or not 0<=entry['size']<=2**50 or not re.fullmatch('[0-9a-f]{64}',entry['sha256']):raise BackupError('corrupt')
                if entry['sha256'] in objects and objects[entry['sha256']]!=entry['size']:raise BackupError('corrupt')
                objects[entry['sha256']]=entry['size']
        for name in names:
            parts=name.split('/')
            if any('/'.join(parts[:i]) in file_names for i in range(1,len(parts))):raise BackupError('unsafe_path')
        if len(m['objects'])!=len(set(m['objects'])) or not set(m['objects'])<=set(objects):raise BackupError('corrupt')
        for name in m['deleted']:relative_name(name)
        if m['secret_policy'] not in ('warn','local','exclude'):raise BackupError('corrupt')
        return objects
    except (KeyError,TypeError,AttributeError):raise BackupError('corrupt') from None


def write_package(destination,manifest,store,tick):
    encoded=canonical(manifest)
    if len(encoded)>MAX_MANIFEST:raise BackupError('format')
    digest=hashlib.sha256(encoded).hexdigest()
    header={'format':'ptm-backup','version':1,'project_id':manifest['project_id'],'id':manifest['id'],
            'key_id':store.key_id,'manifest_size':len(encoded),'manifest_sha256':digest}
    if store.key:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce=os.urandom(12);encoded=nonce+AESGCM(store.key).encrypt(nonce,encoded,canonical(header))
    with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_STORED,allowZip64=True) as archive:
        archive.writestr('format.json',canonical(header))
        archive.writestr('manifest.bin',encoded)
        for sha in sorted(manifest['objects']):
            tick()
            with read_private(store.object_path(sha)) as source,archive.open('objects/'+sha,'w',force_zip64=True) as dest:
                for chunk in iter(lambda:source.read(CHUNK),b''):tick();dest.write(chunk)
    return digest


@contextmanager
def package(path,expected,cfg,tick):
    """Expected digest comes from trusted SQLite, not a sidecar supplied with the ZIP."""
    try:
        with read_private(path) as stream:
            actual,_=digest_stream(stream,tick)
            if actual!=expected['sha256']:raise BackupError('corrupt')
            stream.seek(0)
            with zipfile.ZipFile(stream) as archive:
                members=archive.infolist()
                if len(members)>MAX_ENTRIES:raise BackupError('format')
                names=set()
                for item in members:
                    if item.filename in names:raise BackupError('unsafe_path')
                    names.add(item.filename)
                    if (item.filename not in ('format.json','manifest.bin') and not re.fullmatch('objects/[0-9a-f]{64}',item.filename)) or item.is_dir():
                        raise BackupError('unsafe_path')
                    kind=stat.S_IFMT(item.external_attr>>16)
                    if kind not in (0,stat.S_IFREG) or item.flag_bits&1 or item.compress_type!=zipfile.ZIP_STORED or item.file_size!=item.compress_size:raise BackupError('unsafe_path')
                if not {'format.json','manifest.bin'}<=names:raise BackupError('format')
                if archive.getinfo('format.json').file_size>4096 or archive.getinfo('manifest.bin').file_size>MAX_MANIFEST+28:raise BackupError('format')
                header=json_load(archive.read('format.json'))
                if (header.get('format'),header.get('version'),header.get('project_id'),header.get('id'),header.get('key_id'))!=(
                    'ptm-backup',1,cfg.project_id,expected['id'],expected['key_id']):raise BackupError('corrupt')
                key=load_key(expected['key_id'],cfg)
                data=archive.read('manifest.bin')
                if key:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    from cryptography.exceptions import InvalidTag
                    try:data=AESGCM(key).decrypt(data[:12],data[12:],canonical(header))
                    except (InvalidTag,ValueError):raise BackupError('corrupt') from None
                if len(data)!=header['manifest_size'] or hashlib.sha256(data).hexdigest()!=expected['manifest_sha256'] or header['manifest_sha256']!=expected['manifest_sha256']:
                    raise BackupError('corrupt')
                manifest=json_load(data);objects=validate_manifest(manifest)
                if (manifest['id'],manifest['project_id'],manifest['key_id'])!=(expected['id'],cfg.project_id,expected['key_id']):raise BackupError('corrupt')
                if names!={'format.json','manifest.bin'}|{'objects/'+s for s in manifest['objects']}:raise BackupError('corrupt')
                for digest in manifest['objects']:
                    tick();info=archive.getinfo('objects/'+digest)
                    with archive.open(info) as content:
                        consume(content,info.file_size,key,object_aad(cfg.project_id,expected['key_id'],digest),
                                digest,objects[digest],tick)
                yield manifest,archive
    except FileNotFoundError:raise BackupError('missing') from None
    except (zipfile.BadZipFile,EOFError,KeyError,TypeError,RuntimeError):raise BackupError('corrupt') from None
