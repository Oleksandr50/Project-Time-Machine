"""Explicit public export. No Git push, runtime collection, or private evidence traversal."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[1]
ROOT_FILES=('install.sh','setup.sh','start.sh','INSTALL.md','INSTALL_EN.md','INSTALL_PL.md','INSTALL_UK.md','Install-Windows.ps1','Start-Windows.ps1','Start-Windows.cmd','Dockerfile','compose.yaml',
            '.env.example','.dockerignore','.gitignore','.gitattributes','requirements.txt','requirements.lock','requirements-dev.txt',
            'CHANGELOG.md','CONTRIBUTING.md','SECURITY.md','LICENSE','AUTHORS','COPYRIGHT','THIRD_PARTY_NOTICES.md','README_RU.md','README_PL.md','README_UK.md')
PUBLIC_SCRIPTS=('install.py','manage.py','setup.py','start.py','docker_prepare.py','docker_upgrade.py','verify_installation.py','verify_container.py','run_tests.py','generate_backup_key.py','build_release.py','build_linux_installer.py')
PUBLIC_TESTS=('test_deletions.py','test_interface_access.py','test_lan_network.py','test_release_startup.py','test_linux_installer_config.py','test_stage2.py','test_stage3.py','test_stage4.py','test_stage5.py','test_stage6.py','test_stage7.py')
PUBLIC_DOCS=('installation.md','user-guide.md','updates.md','uninstall.md','licensing.md','authentication.md','backups.md','restore.md','analysis-audit.md','publication-checks.md')


def inventory(root=ROOT):
    root=Path(root);result={}
    for p in (root/'app').rglob('*'):
        rel=p.relative_to(root).as_posix()
        if p.is_file() and '__pycache__' not in p.parts and (p.suffix in ('.py','.html','.css','.js') or p.parent.name=='locales' and p.suffix=='.json'):
            result[rel]=p
    for name in ROOT_FILES:result[name]=root/name
    for name in PUBLIC_SCRIPTS:result['scripts/'+name]=root/'scripts'/name
    for name in PUBLIC_TESTS:result['tests/'+name]=root/'tests'/name
    for name in PUBLIC_DOCS:result['docs/'+name]=root/'docs'/name
    result['README.md']=root/'docs/README-public.md' if (root/'docs/README-public.md').exists() else root/'README.md'
    result['docs/architecture.md']=root/'docs/architecture-public.md' if (root/'docs/architecture-public.md').exists() else root/'docs/architecture.md'
    for source in (root/'third_party').rglob('*'):
        if source.is_file():result[source.relative_to(root).as_posix()]=source
    result['config/settings.example.json']=root/'config/settings.example.json'
    result['.github/workflows/ci.yaml']=root/'.github/workflows/ci.yaml'
    for name,p in result.items():
        if not p.is_file() or p.is_symlink():raise ValueError('Missing or unsafe public source: '+name)
    return result


def inspect_bytes(name,data):
    issues=[]
    if data.startswith(b'SQLite format 3\0'):issues.append('sqlite_database')
    if data.startswith((b'PK\x03\x04',b'\x1f\x8b')):issues.append('unexpected_archive')
    text=data.decode('utf-8',errors='replace')
    if str(Path.home())+'/' in text:issues.append('private_checkout_path')
    patterns={
        'private_key':r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{40,}',
        'api_token':r'\b(?:sk-[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|AIza[A-Za-z0-9_-]{30,})\b',
        'password_hash':r'\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{16,}\$[A-Za-z0-9+/]{20,}',
        'credential_url':r'(?i)https?://[^\s/:]+:[^\s/@]+@[^\s/]+',
    }
    for code,pattern in patterns.items():
        for match in re.finditer(pattern,text):
            # Known synthetic fixtures only; test paths alone never exempt a real match.
            if 'synthetic' not in match[0].lower() and 'example.invalid' not in match[0].lower():issues.append(code)
    return sorted(set(issues))


def scan(directory,history=False):
    directory=Path(directory);findings=[]
    for p in directory.rglob('*'):
        rel=p.relative_to(directory).as_posix()
        if '.git' in p.parts:continue
        if p.is_symlink():findings.append(dict(path=rel,kind='symlink'));continue
        if not p.is_file():continue
        if any(part in ('runtime','.venv','private-backups','checkpoints','docker-state','docker-keys') or part.startswith('private-stage') for part in p.relative_to(directory).parts):
            findings.append(dict(path=rel,kind='private_storage'))
            continue
        if p.name=='.env' or p.name.endswith('.local.json') or p.suffix in ('.db','.sqlite','.sqlite3','.log','.key','.pem'):
            findings.append(dict(path=rel,kind='private_file'))
            continue
        if p.stat().st_size>16*1024*1024:
            findings.append(dict(path=rel,kind='oversized_unreviewed'));continue
        for kind in inspect_bytes(rel,p.read_bytes()):findings.append(dict(path=rel,kind=kind))
    git_status='not_present'
    if history and (directory/'.git').exists():
        check=subprocess.run(['git','-C',str(directory),'rev-parse','--is-inside-work-tree'],capture_output=True,text=True)
        if check.returncode:git_status='unavailable'
        else:
            git_status='scanned'
            objects=subprocess.run(['git','-C',str(directory),'rev-list','--objects','--all'],capture_output=True,text=True,check=True).stdout.splitlines()
            for line in objects:
                oid=line.split(' ',1)[0]
                kind=subprocess.run(['git','-C',str(directory),'cat-file','-t',oid],capture_output=True,text=True,check=True).stdout.strip()
                if kind!='blob':continue
                size=int(subprocess.run(['git','-C',str(directory),'cat-file','-s',oid],capture_output=True,text=True,check=True).stdout)
                if size>16*1024*1024:
                    findings.append(dict(object=oid,kind='oversized_history_blob'));continue
                data=subprocess.run(['git','-C',str(directory),'cat-file','blob',oid],capture_output=True,check=True).stdout
                for code in inspect_bytes('git',data):findings.append(dict(object=oid,kind=code))
    return dict(status='passed' if not findings and git_status!='unavailable' else 'failed',findings=findings,git_history=git_status)


def build(destination,root=ROOT):
    from .version import VERSION
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
    target=destination/('project-time-machine-'+VERSION)
    if target.exists():raise ValueError('Export already exists; choose a new output directory')
    with tempfile.TemporaryDirectory(prefix='.public-',dir=destination) as tmp:
        tree=Path(tmp)/target.name;tree.mkdir()
        for name,source in inventory(root).items():
            p=tree/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,p)
            p.chmod(0o755 if p.suffix=='.sh' else 0o644)
        (tree/'examples').mkdir()
        (tree/'examples/hello.py').write_text('def hello():\n    return "Hello, Project Time Machine"\n')
        report=scan(tree)
        if report['status']!='passed':raise ValueError('Public export scan failed: '+json.dumps(report))
        manifest={p.relative_to(tree).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in tree.rglob('*') if p.is_file()}
        (tree/'release-manifest.json').write_text(json.dumps(dict(version=VERSION,files=manifest),indent=2)+'\n')
        shutil.move(tree,target)
    archive=destination/(target.name+'.tar.gz')
    def public_metadata(member):
        # Public packages must not disclose the builder's OS account or file times.
        member.uid=member.gid=0;member.uname=member.gname='';member.mtime=0
        member.pax_headers={}
        return member
    with tarfile.open(archive,'w:gz') as t:t.add(target,arcname=target.name,filter=public_metadata)
    with tarfile.open(archive) as t:
        for name,value in manifest.items():
            assert hashlib.sha256(t.extractfile(target.name+'/'+name).read()).hexdigest()==value
    sha=hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(archive.suffix+'.sha256').write_text(sha+'  '+archive.name+'\n')
    result=dict(status='verified',version=VERSION,files=len(manifest),sha256=sha,scan=report,published=False)
    (destination/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
