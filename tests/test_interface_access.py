"""Default direct-interface access and one-time remote setup owner proof."""
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
import json,os,tempfile,unittest
import test_stage2 as stage2
from app import auth,projects,config,interfaces,setup_codes


class DirectInterfaceTests(stage2.AuthFixture):
    def setUp(self):
        super().setUp()
        self.cfg=replace(self.cfg,lan_access=True,management_networks=None,remote_setup=True)
        projects.base_settings=self.cfg;projects.current_settings.set(self.cfg)
        self.nic_patch=patch.object(interfaces,'_snapshot',return_value=(frozenset(('127.0.0.1','::1','100.64.0.10','192.168.77.10','203.0.113.5')),frozenset(('localhost','test-server'))))
        self.nic_patch.start();self.addCleanup(self.nic_patch.stop)
        setup_codes.ensure(self.cfg);self.code=setup_codes.read(self.cfg)
    def remote(self,host='100.64.0.10',peer='100.101.0.20'):
        return self.client(host='http://'+host+':13011',peer=peer)
    def create_remotely(self):
        client=self.remote();self.assertEqual(client.get('/setup').status_code,200)
        result=self.post(client,'/setup',dict(username='owner',password=stage2.PASSWORD,confirm_password=stage2.PASSWORD,setup_code=self.code,language='en'))
        self.assertEqual(result.status_code,303,result.text)
        return client
    def test_remote_first_admin_requires_correct_owner_code(self):
        client=self.remote();response=client.get('/setup');self.assertEqual(response.status_code,200)
        self.assertIn('name="setup_code"',response.text);self.assertNotIn(self.code,response.text)
        for value in ('','0'*64):
            result=self.post(client,'/setup',dict(username='owner',password=stage2.PASSWORD,confirm_password=stage2.PASSWORD,setup_code=value))
            self.assertEqual(result.status_code,403)
        with projects.registry() as conn:self.assertEqual(conn.execute('SELECT count(*) FROM users').fetchone()[0],0)
        self.create_remotely();self.assertFalse(setup_codes.path(self.cfg).exists())
    def test_all_assigned_interface_addresses_allow_authenticated_access(self):
        self.create_remotely()
        for host,peer in [('100.64.0.10','100.101.0.20'),('192.168.77.10','192.168.77.20'),('203.0.113.5','198.51.100.4'),('test-server','100.101.0.21')]:
            client=self.remote(host,peer);self.signin(client)
            self.assertEqual(client.get('/').status_code,200,(host,peer))
            self.assertEqual(client.get('/account').status_code,200)
    def test_unknown_host_is_not_treated_as_an_interface(self):
        self.assertEqual(self.remote('unrelated.example').get('/setup').status_code,403)
        self.assertEqual(self.remote('8.8.8.8').get('/setup').status_code,403)
    def test_network_setup_remains_single_use(self):
        first=self.remote();second=self.remote()
        first.get('/setup');second.get('/setup')
        self.assertEqual(self.post(first,'/setup',dict(username='owner',password=stage2.PASSWORD,confirm_password=stage2.PASSWORD,setup_code=self.code)).status_code,303)
        self.assertEqual(self.post(second,'/setup',dict(username='another',password=stage2.PASSWORD,confirm_password=stage2.PASSWORD,setup_code=self.code)).status_code,410)
        with projects.registry() as conn:self.assertEqual(conn.execute('SELECT count(*) FROM users').fetchone()[0],1)
    def test_proxy_headers_do_not_bypass_owner_proof_or_https(self):
        self.assertEqual(self.remote().get('/setup',headers={'x-forwarded-for':'127.0.0.1'}).status_code,403)
    def test_explicit_allowlist_and_network_disable_remain_authoritative(self):
        admin=self.create_remotely()
        self.assertEqual(self.post(admin,'/admin/network',dict(enabled='off',current_password=stage2.PASSWORD)).status_code,303)
        self.assertEqual(self.remote().get('/login').status_code,403)
        projects.base_settings=replace(self.cfg,management_networks=('127.0.0.0/8',))
        self.assertEqual(self.remote().get('/login').status_code,403)
    def test_setup_code_permissions_and_restart_stability(self):
        setup_codes.ensure(self.cfg);self.assertEqual(setup_codes.read(self.cfg),self.code)
        path=setup_codes.path(self.cfg);self.assertEqual(path.stat().st_mode&0o777,0o600)
        path.chmod(0o644);self.assertFalse(setup_codes.valid(self.cfg,self.code))
    def test_local_peer_with_network_host_still_requires_code(self):
        client=self.remote(peer='127.0.0.1');self.assertEqual(client.get('/setup').status_code,200)
        self.assertEqual(self.post(client,'/setup',dict(username='owner',password=stage2.PASSWORD,confirm_password=stage2.PASSWORD)).status_code,403)
    def test_ipv4_mapped_vpn_addresses_are_recognized(self):
        client=self.remote('[::ffff:100.64.0.10]','::ffff:100.101.0.20')
        self.assertEqual(client.get('/setup').status_code,200)


if __name__=='__main__':unittest.main()
