"""Start the selected installation without depending on the caller's directory."""
from pathlib import Path
import argparse,os,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.installation import default_prefix,prefix_path,layout
parser=argparse.ArgumentParser();parser.add_argument('--prefix',default=os.environ.get('PTM_PREFIX',str(default_prefix())))
args=parser.parse_args()
try:
    prefix=prefix_path(args.prefix);layout(prefix)
    launcher=prefix/'bin/ptm';os.execv(launcher,[str(launcher),'start'])
except (ValueError,OSError) as exc:parser.exit(1,str(exc)+'\n')
