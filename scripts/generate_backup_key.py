"""Provision a 256-bit key outside source/archive storage. Never prints key material."""
import argparse
import os
from pathlib import Path
import secrets
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.config import base_settings
from app.filesystem import absolute,inside
from app.backup_storage import private_dir,fsync_dir


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path',help='Absolute path in a separate private key directory')
    args=parser.parse_args()
    path=absolute(args.path)
    prohibited=(base_settings.app_root,base_settings.backups_dir,base_settings.content_dir,
                base_settings.temp_dir,*base_settings.allowed_roots)
    if any(inside(path,Path(root).resolve()) for root in prohibited):
        parser.error('Choose a key directory outside application, projects, content, backups and temp')
    private_dir(path.parent)
    from app.filesystem import open_directory
    with open_directory(path.parent) as directory:
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        with os.fdopen(fd,'wb') as out:out.write(secrets.token_bytes(32));out.flush();os.fsync(out.fileno())
        os.fsync(directory)
    print('Key created with private permissions. Store a separate protected copy before use.')


if __name__=='__main__':main()
