"""Disposable real engine test for a fresh install; no external dependencies or user project access."""
import json
import os
from pathlib import Path
import secrets
import tempfile


def main():
    with tempfile.TemporaryDirectory(prefix='ptm-selftest-') as temp:
        root=Path(temp);source=root/'projects/test';source.mkdir(parents=True)
        cfg={k:str(root/v) for k,v in dict(app_root='application',config_dir='config',data_dir='state',backups_dir='backups',metadata_dir='metadata',reports_dir='reports',content_dir='content',logs_dir='logs',temp_dir='tmp',migrations_dir='migrations').items()}
        cfg.update(allowed_roots=[str(root/'projects')],db_path=str(root/'state/unselected.sqlite'));config=root/'settings.json';config.write_text(json.dumps(cfg));os.environ['PTM_CONFIG']=str(config)
        # These imports must follow the isolated configuration, not the installed user's config.
        from . import projects,auth,services,backups,restores,jobs
        for key in ('db_path','config_dir','data_dir','backups_dir','metadata_dir','reports_dir','content_dir','logs_dir','temp_dir','migrations_dir'):
            if not Path(getattr(projects.base_settings,key)).is_relative_to(root):raise ValueError('Self-test storage escaped its temporary directory')
        raw=auth.anonymous('127.0.0.1');raw=auth.bootstrap(auth.digest(raw),'selftest',secrets.token_urlsafe(32),'127.0.0.1')
        (source/'hello.py').write_text('def hello():\n    return 1\n')
        pid=projects.add_project(str(source),'Self test');token=projects.current_settings.set(projects.project_settings(projects.get_project(pid)))
        try:
            services.run_analysis('installation self test');point=backups.create('full',actor_id=auth.session(raw)['user_id'])
            (source/'hello.py').write_text('changed\n');user=auth.session(raw)
            preview=restores.preview(user,raw,'point',point['point_id'])
            result=restores.confirm(user,raw,preview['id'],preview['token'],'on','RESTORE')
            jid=result if isinstance(result,str) else result['job_id']
            jobs.execute(jid)
            if (source/'hello.py').read_text()!='def hello():\n    return 1\n':raise ValueError('Engine restore self test failed')
            if not any(p['kind']=='pre_restore' and p['protected'] for p in backups.points()):raise ValueError('Missing protected insurance')
        finally:projects.current_settings.reset(token)
    print(json.dumps(dict(status='passed',checks=['metadata snapshot','full backup','confirmed restore','protected pre-restore'],user_projects_accessed=False)))


if __name__=='__main__':main()
