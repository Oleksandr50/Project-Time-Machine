"""Only 0.7.3 bind/LAN authorization checks; all databases/projects are temporary."""
from dataclasses import replace
from pathlib import Path
from http.cookies import SimpleCookie
from urllib.request import build_opener,ProxyHandler,HTTPCookieProcessor,Request
from urllib.parse import urlencode
from http.cookiejar import CookieJar
from unittest.mock import patch
import http.client,ipaddress,json,os,secrets,shlex,socket,subprocess,sys,tarfile,tempfile,unittest
import test_stage2 as stage2
from app import auth,projects,security,installation,config


class LanNetworkTests(stage2.AuthFixture):
    def setUp(self):
        super().setUp()
        self.cfg=replace(self.cfg,lan_access=True,remote_setup=False,management_networks=config.LOOPBACK_NETWORKS+config.PRIVATE_NETWORKS)
        projects.base_settings=self.cfg;projects.current_settings.set(self.cfg)
    def lan(self,peer='192.168.50.22',host='http://192.168.50.10:13011'):
        return self.client(host=host,peer=peer)
    def test_default_policy_allows_private_networks_but_not_reserved_or_public_addresses(self):
        self.assertEqual(installation.fresh_installation_info(self.root/'install',13011)['bind_address'],'0.0.0.0')
        self.assertTrue(config.Settings().lan_access)
        for peer in ('10.2.3.4','172.19.1.2','192.168.50.22','169.254.10.20','fd42::2','fe80::2','100.64.0.10','::ffff:192.168.50.22'):
            self.assertTrue(security.lan_address(peer),peer)
        for peer in ('8.8.8.8','203.0.113.20','198.51.100.1','2001:db8::1'):
            self.assertFalse(security.lan_address(peer),peer)
    def test_wildcard_boot_does_not_enable_remote_initial_administrator_creation(self):
        client=self.lan()
        self.assertEqual(client.get('/setup').status_code,403)
        self.assertEqual(client.post('/setup',data={'username':'intruder','password':'synthetic-password'}).status_code,403)
        self.assertEqual(client.get('/healthz').status_code,403)
        with projects.registry() as db:self.assertEqual(db.execute('SELECT count(*) FROM users').fetchone()[0],0)
    def test_lan_http_login_works_without_manual_network_checkbox_or_json_changes(self):
        self.setup();client=self.lan();self.signin(client)
        self.assertEqual(client.get('/').status_code,200)
        self.assertEqual(client.get('/account').status_code,200)
        self.assertTrue(auth.state()['network_enabled'])
        with projects.registry() as db:
            self.assertEqual(db.execute('SELECT network_enabled FROM auth_settings').fetchone()[0],0)
            self.assertFalse(db.execute("SELECT 1 FROM user_audit WHERE event IN ('network_enabled','network_disabled')").fetchone())
    def test_unauthenticated_lan_cannot_read_application_data(self):
        self.setup();client=self.lan()
        self.assertEqual(client.get('/api/status').status_code,401)
        self.assertEqual(client.get('/',follow_redirects=False).headers['location'],'/login')
    def test_explicit_network_disable_is_respected_and_survives_configuration_reload(self):
        self.setup();client=self.lan();self.signin(client)
        result=self.post(self.admin,'/admin/network',{'enabled':'off','current_password':stage2.PASSWORD})
        self.assertEqual(result.status_code,303);self.assertFalse(auth.state()['network_enabled'])
        self.assertEqual(client.get('/login').status_code,403)
        projects.base_settings=replace(self.cfg);self.assertFalse(auth.state()['network_enabled'])
        self.assertEqual(self.post(self.admin,'/admin/network',{'enabled':'on','current_password':stage2.PASSWORD}).status_code,303)
        self.assertEqual(client.get('/login').status_code,200)
    def test_public_peers_and_untrusted_dns_hosts_remain_denied(self):
        self.setup()
        for peer in ('8.8.8.8','203.0.113.20'):
            self.assertEqual(self.lan(peer=peer).get('/login').status_code,403)
        self.assertEqual(self.lan(host='http://untrusted.example:13011').get('/login').status_code,403)
    def test_forwarded_headers_do_not_turn_untrusted_http_into_trusted_lan_or_localhost(self):
        self.setup();client=self.lan()
        self.assertEqual(client.get('/login',headers={'x-forwarded-for':'127.0.0.1','x-forwarded-proto':'https'}).status_code,403)
    def test_explicit_allowlist_and_strict_https_profile_are_not_overridden(self):
        self.setup()
        projects.base_settings=replace(self.cfg,management_networks=('127.0.0.0/8',))
        self.assertEqual(self.lan().get('/login').status_code,403)
        projects.base_settings=replace(self.cfg,lan_access=False)
        self.assertEqual(self.post(self.admin,'/admin/network',{'enabled':'on','current_password':stage2.PASSWORD}).status_code,303)
        self.assertEqual(self.lan().get('/login').status_code,403)
        self.assertEqual(self.lan(host='https://192.168.50.10:13011').get('/login').status_code,200)
    def test_lan_keeps_csrf_roles_and_session_cookie_protection(self):
        self.setup();self.create_user('viewer','viewer');client=self.lan();self.signin(client,'viewer',stage2.USER_PASSWORD)
        self.assertEqual(client.post('/account/preferences',data={'language':'en'}).status_code,403)
        self.assertEqual(self.post(client,'/admin/users/create',{'username':'elevate','password':'synthetic-password-long','current_password':stage2.USER_PASSWORD}).status_code,403)
        self.assertEqual(client.get('/account').status_code,200)
        session=next(cookie for cookie in client.cookies.jar if cookie.name==auth.COOKIE)
        self.assertIn('HttpOnly',session._rest);self.assertEqual(session._rest.get('SameSite'),'strict')
    def test_bad_password_and_login_rate_limits_still_apply_over_lan(self):
        self.setup();projects.base_settings=replace(self.cfg,login_attempt_limit=2)
        client=self.lan();self.assertEqual(client.get('/login').status_code,200)
        for _ in range(2):self.assertEqual(self.post(client,'/login',{'username':'owner','password':'wrong'}).status_code,401)
        self.assertEqual(self.post(client,'/login',{'username':'owner','password':'wrong'}).status_code,429)


class WildcardStartupTest(unittest.TestCase):
    def test_real_wildcard_startup_before_setup_and_actual_lan_http_login(self):
        if not os.environ.get('PTM_NETWORK_ARCHIVE'):self.skipTest('Set PTM_NETWORK_ARCHIVE for the focused TCP startup check')
        with tempfile.TemporaryDirectory(prefix='ptm-lan-startup-') as tmp:
            prefix=Path(tmp)/'custom installation';prefix.mkdir(mode=0o700);release=prefix/'releases/network-release'
            with tarfile.open(os.environ['PTM_NETWORK_ARCHIVE']) as archive:
                for member in archive.getmembers():
                    if member.isfile() and member.name.split('/',1)[1].startswith('app/'):
                        target=release/member.name.split('/',1)[1];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.extractfile(member).read())
            interpreter=release/'venv/bin/python';interpreter.parent.mkdir(parents=True)
            interpreter.write_text('#!/bin/sh\nexec '+shlex.quote(sys.executable)+' "$@"\n');interpreter.chmod(0o755)
            doc=installation.fresh_configuration(prefix);doc.update(allowed_roots=[tmp],remote_setup=False,management_networks=list(config.LOOPBACK_NETWORKS+config.PRIVATE_NETWORKS))
            for key in ('config_dir','data_dir','backups_dir','reports_dir','metadata_dir','content_dir','logs_dir','temp_dir','migrations_dir'):Path(doc[key]).mkdir(parents=True,exist_ok=True)
            with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
            installation.atomic_json(prefix/'config/settings.json',doc)
            installation.atomic_json(prefix/'installation.json',installation.fresh_installation_info(prefix,port))
            installation.activate(prefix,release)
            before=(prefix/'config/settings.json').read_bytes();children=[];real_popen=subprocess.Popen
            def track(*args,**kwargs):
                child=real_popen(*args,**kwargs);children.append(child);return child
            try:
                with patch.object(installation.subprocess,'Popen',side_effect=track):installation.start(prefix)
                listens=Path('/proc/net/tcp').read_text().splitlines()[1:]
                self.assertTrue(any(row.split()[1]=='00000000:'+format(port,'04X') and row.split()[3]=='0A' for row in listens))
                # Discover only local interface addresses; never contact an external service.
                addresses=subprocess.run(['hostname','-I'],capture_output=True,text=True,check=True).stdout.split()
                candidates=[value for value in addresses if ':' not in value and security.lan_address(value)]
                self.assertTrue(candidates,'This focused LAN check needs a local private IPv4 interface')
                address=candidates[0];cookies={}
                def remote(path,data=None):
                    connection=http.client.HTTPConnection(address,port,timeout=5,source_address=(address,0))
                    headers={'Origin':'http://'+address+':'+str(port)}
                    if cookies:headers['Cookie']='; '.join(k+'='+v for k,v in cookies.items())
                    if data is not None:
                        headers['Content-Type']='application/x-www-form-urlencoded';data=urlencode({'csrf_token':cookies.get('ptm_csrf',''),**data})
                    try:
                        connection.request('POST' if data is not None else 'GET',path,body=data,headers=headers)
                        response=connection.getresponse();body=response.read()
                        for header,value in response.getheaders():
                            if header.lower()=='set-cookie':
                                parsed=SimpleCookie();parsed.load(value);cookies.update({k:v.value for k,v in parsed.items()})
                        return response.status,body
                    finally:connection.close()
                self.assertEqual(remote('/setup')[0],403);self.assertEqual(remote('/healthz')[0],403)
                jar=CookieJar();opener=build_opener(ProxyHandler({}),HTTPCookieProcessor(jar));base='http://127.0.0.1:'+str(port)
                with opener.open(base+'/setup',timeout=5) as response:self.assertEqual(response.status,200)
                password=secrets.token_urlsafe(24);csrf=next(c.value for c in jar if c.name=='ptm_csrf')
                form=urlencode(dict(csrf_token=csrf,username='temporary-admin',password=password,confirm_password=password,language='en')).encode()
                with opener.open(Request(base+'/setup',data=form,headers={'Origin':base}),timeout=5) as response:self.assertEqual(response.status,200)
                self.assertEqual(remote('/login')[0],200)
                self.assertEqual(remote('/login',dict(username='temporary-admin',password=password,language='en'))[0],303)
                self.assertEqual(remote('/')[0],200)
                self.assertEqual((prefix/'config/settings.json').read_bytes(),before)
            finally:
                installation.stop(prefix)
                for child in children:
                    if child.poll() is None:child.wait(timeout=10)


if __name__=='__main__':unittest.main()
