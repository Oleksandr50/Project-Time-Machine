"""Build a clean local export; never publishes to a remote service."""
from pathlib import Path
import argparse,json,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.release import build,scan
p=argparse.ArgumentParser();p.add_argument('--output',default='dist');p.add_argument('--scan');p.add_argument('--history',action='store_true')
args=p.parse_args();result=scan(args.scan,history=args.history) if args.scan else build(args.output)
print(json.dumps(result,indent=2));sys.exit(result['status'] not in ('passed','verified'))
