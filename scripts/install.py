"""Dependency-free installer entrypoint; optional wheels allow fully offline installation."""
from pathlib import Path
import argparse,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.installation import install,default_prefix
p=argparse.ArgumentParser(description='Install Project Time Machine without sudo')
p.add_argument('--prefix',default=str(default_prefix()))
p.add_argument('--port',type=int);p.add_argument('--projects-root');p.add_argument('--wheelhouse');p.add_argument('--no-start',action='store_true');p.add_argument('--service',action='store_true')
a=p.parse_args()
try:print(json.dumps(install(Path(__file__).resolve().parents[1],a.prefix,a.port,a.projects_root,a.wheelhouse,a.no_start,a.service),indent=2))
except (OSError,ValueError) as e:p.exit(1,str(e)+'\n')
