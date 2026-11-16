"""Build a runtime-only Linux distribution; never installs or imports the application."""
from pathlib import Path
from io import BytesIO
import argparse,ast,gzip,hashlib,json,tarfile

ROOT=Path(__file__).resolve().parents[1]


def build(output):
    version=ast.literal_eval(ast.parse((ROOT/'app/version.py').read_text()).body[0].value)
    archive_name='project-time-machine-'+version+'-linux.tar.gz';top='project-time-machine-'+version
    names=['install.sh','setup.sh','start.sh','INSTALL.md','INSTALL_EN.md','INSTALL_PL.md','INSTALL_UK.md','LICENSE','AUTHORS','COPYRIGHT','THIRD_PARTY_NOTICES.md','requirements.txt','requirements.lock','config/settings.example.json']
    names += ['scripts/'+n for n in ('install.py','setup.py','start.py','manage.py','generate_backup_key.py')]
    names += [p.relative_to(ROOT).as_posix() for p in (ROOT/'app').rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='release.py' and (p.suffix in ('.py','.html','.css','.js') or p.parent.name=='locales' and p.suffix=='.json')]
    names += [p.relative_to(ROOT).as_posix() for p in (ROOT/'third_party').rglob('*') if p.is_file()]
    files={}
    for name in sorted(names):
        p=ROOT/name
        if not p.is_file() or p.is_symlink():raise ValueError('Missing/unsafe runtime file: '+name)
        data=p.read_bytes()
        if data.startswith(b'SQLite format 3\0') or (str(Path.home())+'/').encode() in data:raise ValueError('Private data/path in '+name)
        files[name]=data
    manifest={'version':version,'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
    files['release-manifest.json']=(json.dumps(manifest,indent=2)+'\n').encode()
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    archive=output/archive_name
    with archive.open('xb') as destination,gzip.GzipFile(filename='',fileobj=destination,mode='wb',mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w') as t:
        directories={top}
        for name in files:
            directories.update(str(p) for p in (Path(top)/name).parents if str(p)!='.')
        for name in sorted(directories):
            info=tarfile.TarInfo(name);info.type=tarfile.DIRTYPE;info.mode=0o755;t.addfile(info)
        for name,data in sorted(files.items()):
            info=tarfile.TarInfo(top+'/'+name);info.mode=0o755 if name.endswith('.sh') else 0o644;info.size=len(data);t.addfile(info,BytesIO(data))
    with tarfile.open(archive) as t:
        actual={str(Path(m.name).relative_to(top)):t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
        if actual!=files:raise ValueError('Archive contents differ')
        if any(m.issym() or m.islnk() or m.uid or m.gid or m.uname or m.gname for m in t.getmembers()):raise ValueError('Unexpected archive metadata')
    for name in ('INSTALL.md','INSTALL_EN.md','INSTALL_PL.md','INSTALL_UK.md'):(output/name).write_bytes(files[name])
    sums=''
    for name in (archive_name,'INSTALL.md','INSTALL_EN.md','INSTALL_PL.md','INSTALL_UK.md'):sums+=hashlib.sha256((output/name).read_bytes()).hexdigest()+'  '+name+'\n'
    (output/'SHA256SUMS').write_text(sums)
    return dict(archive=str(archive.resolve()),version=version,bytes=archive.stat().st_size,sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),runtime_files=len(files),manifest='verified')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',default=str(ROOT/('dist/linux-installer-'+ast.literal_eval(ast.parse((ROOT/'app/version.py').read_text()).body[0].value))))
    print(json.dumps(build(parser.parse_args().output),indent=2))
