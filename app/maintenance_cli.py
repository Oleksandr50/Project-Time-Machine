"""Offline container maintenance. A pending deployment blocks startup until explicit recovery."""
from pathlib import Path
import argparse,json,uuid
from . import projects,maintenance
from .lifecycle import guard


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=('backup-state','prepare-upgrade','recover-update'));a=p.parse_args()
    cfg=projects.base_settings;journal=cfg.data_dir/'deployment-journal.json'
    with guard(cfg.data_dir,exclusive=True):
        if a.command=='recover-update':
            state=json.loads(journal.read_text())
            if state['phase']=='complete':raise ValueError('Deployment completed; database rollback is not automatic after startup')
            point=Path(state['checkpoint']).resolve()
            if not point.is_relative_to(cfg.migrations_dir.resolve()/'deployments'):raise ValueError('Unsafe recovery checkpoint')
            if state['phase']=='migrating':maintenance.recover(cfg,point)
            state['phase']='complete';state['recovered']=True;maintenance.atomic_json(journal,state)
            print(json.dumps(dict(status='recovered',checkpoint=str(point))));return
        if journal.exists() and json.loads(journal.read_text())['phase']!='complete':raise ValueError('An interrupted deployment requires recover-update')
        point=cfg.migrations_dir/'deployments'/uuid.uuid4().hex
        state=dict(phase='preparing',checkpoint=str(point))
        if a.command=='prepare-upgrade':maintenance.atomic_json(journal,state)
        maintenance.checkpoint(cfg,point)
        if a.command=='prepare-upgrade':
            maintenance.rehearse(point);state['phase']='migrating';maintenance.atomic_json(journal,state)
            maintenance.migrate_checked(cfg,point);state['phase']='complete';maintenance.atomic_json(journal,state)
        print(json.dumps(dict(status='verified',checkpoint=str(point),archives_unchanged=True)))


if __name__=='__main__':main()
