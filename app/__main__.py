"""Bind and HTTP authorization are independent; lifecycle guard precedes migrations."""
import ipaddress
import os
import uvicorn
from . import projects
from .lifecycle import guard

if __name__=='__main__':
    cfg=projects.base_settings
    with guard(cfg.data_dir):
        host=os.environ.get('PTM_HOST','127.0.0.1')
        ipaddress.ip_address(host)  # Validate bind; HTTP middleware protects setup/login/data.
        if cfg.remote_setup and cfg.lan_access:
            from . import auth,setup_codes
            if not auth.state()['setup_completed']:setup_codes.ensure(cfg)
        cert=os.environ.get('PTM_TLS_CERT');key=os.environ.get('PTM_TLS_KEY')
        if bool(cert)!=bool(key):raise SystemExit('Укажите и PTM_TLS_CERT, и PTM_TLS_KEY')
        uvicorn.run('app.main:app',host=host,port=int(os.environ.get('PTM_PORT','13011')),
                    proxy_headers=bool(cfg.trusted_proxies),forwarded_allow_ips=list(cfg.trusted_proxies),
                    ssl_certfile=cert,ssl_keyfile=key,access_log=False)
