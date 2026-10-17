import io
import json
from pathlib import Path
import secrets
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import quote

from reworkbench.engine import analyze
from reworkbench.storage import MAX_FILE
from reworkbench.webapp import APIError, ASSETS, LocalServer, Workbench, authorize, filename, public_summary


class FakeJobs:
    def __init__(self, root, publish):
        self.root, self.publish = root, publish
        self.submitted = []
        self.cancelled = False
    def submit(self, path, modules):
        self.submitted.append((path, modules))
    def cancel(self):
        self.cancelled = True
    def close(self):
        pass


class WebAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        with patch('reworkbench.webapp.Jobs', FakeJobs):
            self.app = Workbench(self.root / 'store')
        self.addCleanup(self.app.close)

    def upload_and_complete(self, mode='static', data=b'hello https://example.org\nerror: harmless fixture'):
        job = self.app.upload(io.BytesIO(data), len(data), quote('zararsız test.txt'), mode)
        path, modules = self.app.jobs.submitted[-1]
        result = analyze(self.app.store, path, modules, threading.Event())
        self.app.publish('result', result)
        return job['id'], result

    def test_mode_selection_upload_report_and_history(self):
        job_id, result = self.upload_and_complete('reverse')
        item = self.app.get('/api/jobs/' + job_id, {})
        self.assertEqual(item['state'], 'completed')
        self.assertEqual(result['file']['name'], 'zararsız test.txt')
        self.assertIn('disassembly', result['modules'])
        self.assertIn('metrics', result['modules'])
        self.assertNotIn('report', item)
        self.assertNotIn('upload_dir', item)
        self.assertIsNone(self.app.active)
        self.assertFalse(list((self.app.store.root / 'uploads').iterdir()))
        self.assertEqual(len(self.app.get('/api/history', {})['jobs']), 1)
        self.assertEqual(self.app.report(job_id)['file']['hashes'], result['file']['hashes'])
        with patch('reworkbench.webapp.Jobs', FakeJobs):
            restored = Workbench(self.app.store.root)
        self.addCleanup(restored.close)
        self.assertIn(result['run_id'], restored.records)
        self.assertEqual(restored.report(result['run_id'])['run_id'], result['run_id'])

    def test_filter_pagination_hex_and_traversal(self):
        job_id, _ = self.upload_and_complete()
        view = self.app.view(job_id, {'tab':['strings'], 'q':['example.org'], 'limit':['1']})
        self.assertEqual(view['total'], 1)
        self.assertIn('example.org', view['rows'][0]['text'])
        view = self.app.view(job_id, {'tab':['indicators'], 'kind':['url']})
        self.assertEqual(view['total'], 1)
        self.assertEqual(view['rows'][0]['kind'], 'url')
        view = self.app.view(job_id, {'tab':['hex'], 'address':['0x4']})
        self.assertIn('00000004', view['text'])
        for query in ({'tab':['hex'],'address':['-1']}, {'tab':['hex'],'address':['0xfffffff']}, {'tab':['../../etc/passwd']}, {'offset':['bad']}):
            with self.assertRaises(APIError):
                self.app.view(job_id, query)
        with self.assertRaises(APIError):
            self.app.get('/api/jobs/../../etc/passwd', {})

    def test_upload_limits_paths_and_partial_cleanup(self):
        for name in ['../escape', '%2e%2e%2fescape', 'dir%5Cfile', '.', 'a%00b']:
            with self.assertRaises(APIError):
                self.app.upload(io.BytesIO(b'x'), 1, name, 'static')
        self.assertEqual(filename(quote('güvenli dosya.bin')), 'güvenli dosya.bin')
        with self.assertRaises(APIError):
            self.app.upload(io.BytesIO(b''), MAX_FILE+1, 'huge', 'static')
        with self.assertRaises(APIError):
            self.app.upload(io.BytesIO(b'x'), 100, 'partial', 'static')
        self.assertFalse(self.app.uploading)
        self.assertFalse(list((self.app.store.root / 'uploads').iterdir()))
        with self.assertRaises(APIError):
            self.app.upload(io.BytesIO(b'x'), 1, 'fixture', 'invented')

    def test_only_one_active_job_and_cancel(self):
        self.app.upload(io.BytesIO(b'x'), 1, 'one', 'static')
        with self.assertRaises(APIError) as caught:
            self.app.upload(io.BytesIO(b'x'), 1, 'two', 'static')
        self.assertEqual(caught.exception.status, 409)
        self.app.action('/api/cancel', {})
        self.assertTrue(self.app.jobs.cancelled)
        self.app.publish('cancelled', 'İptal edildi')
        self.assertIsNone(self.app.active)
        self.assertFalse(list((self.app.store.root / 'uploads').iterdir()))

    def test_no_mcp_call_or_dynamic_run_without_approval(self):
        for endpoint in ('/api/mcp/prepare', '/api/mcp/call', '/api/dynamic/run'):
            with self.assertRaises(APIError):
                self.app.action(endpoint, {'ticket':'invented', 'confirmed':False})
        self.assertNotIn('result', self.app.get('/api/mcp', {}))

    @unittest.skipUnless(__import__('importlib.util', fromlist=['find_spec']).find_spec('jsonschema'), 'jsonschema yok')
    def test_mcp_preview_keeps_exact_arguments_and_requires_confirmation(self):
        from reworkbench.mcp_client import MCP, Config
        self.app.mcp = MCP(Config(url='https://example.invalid/mcp'))
        self.app.mcp.tools['runtime_tool'] = {'name':'runtime_tool','callable':True,'inputSchema':{'type':'object'}}
        self.app.mcp_state = {'state':'connected','tools':list(self.app.mcp.tools.values())}
        arguments = {'text':'<script>untrusted</script>'}
        plan = self.app.action('/api/mcp/prepare', {'name':'runtime_tool','arguments':arguments})
        self.assertIn('<script>', plan['payload'])
        with self.assertRaises(APIError) as caught:
            self.app.action('/api/mcp/call', {'ticket':plan['ticket'],'confirmed':False})
        self.assertEqual(caught.exception.status,403)
        self.assertTrue(self.app.mcp_queue.empty())
        arguments['text']='changed'
        self.app.action('/api/mcp/call', {'ticket':plan['ticket'],'confirmed':True})
        action,ticket=self.app.mcp_queue.get_nowait()
        self.assertEqual(action,'call')
        self.assertEqual(self.app.mcp.consume(ticket),('runtime_tool',{'text':'<script>untrusted</script>'}))

    def test_browser_assets_and_no_external_dependencies(self):
        html = (ASSETS / 'index.html').read_text()
        self.assertIn('Statik Analiz', html)
        self.assertIn('Tersine Mühendislik', html)
        self.assertIn('aria-pressed="true"', html)
        for item in ('app.js','style.css','favicon.svg'):
            self.assertTrue((ASSETS/item).is_file())
        js = (ASSETS / 'app.js').read_text()
        self.assertNotIn('innerHTML', js)
        self.assertNotIn('eval(', js)
        self.assertNotIn('https://', html)

    def test_source_name_is_only_text(self):
        job_id, result = self.upload_and_complete(data=b'<script>alert(1)</script>\n')
        view = self.app.view(job_id, {'tab':['strings']})
        self.assertIn('<script>', view['rows'][0]['text'])
        self.assertEqual(public_summary(result)['file']['hashes'], result['file']['hashes'])


class WebAuthTests(unittest.TestCase):
    def test_auth_host_origin_and_fetch_site(self):
        origin='http://127.0.0.1:8780'
        token=secrets.token_urlsafe(32)
        headers={'Host':'127.0.0.1:8780','Authorization':'Bearer '+token,'Origin':origin,'Sec-Fetch-Site':'same-origin'}
        authorize(headers, origin, token, mutation=True)
        for key, value in [('Authorization','Bearer wrong'),('Host','evil.example'),('Origin','https://evil.example'),('Sec-Fetch-Site','cross-site')]:
            with self.assertRaises(APIError):
                authorize({**headers,key:value}, origin, token, mutation=True)
        with self.assertRaises(APIError):
            authorize({'Host':headers['Host'],'Authorization':headers['Authorization']}, origin, token, mutation=True)

    def test_never_bind_public_interface(self):
        with self.assertRaises(ValueError):
            LocalServer(('0.0.0.0',8780), None, 'fixture')


class RealWebWorkerTests(unittest.TestCase):
    def test_uploaded_file_real_worker_to_table(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Workbench(directory)
            try:
                payload=b'Hello from the browser workflow https://example.org/docs\n'
                job=app.upload(io.BytesIO(payload),len(payload),'fixture.txt','static')
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    item=app.record(job['id'])
                    if item['state'] in ('completed','error','cancelled'):
                        break
                    time.sleep(.05)
                self.assertEqual(item['state'],'completed',item)
                self.assertTrue(app.view(job['id'],{'tab':['strings']})['rows'])
                self.assertTrue(app.get('/api/history',{})['jobs'])
            finally:
                app.close()


class WebHTTPTests(unittest.TestCase):
    def test_http_assets_auth_upload_and_download(self):
        import http.client
        import socket
        try:
            with socket.socket():
                pass
        except PermissionError:
            self.skipTest('Ortam TCP soket oluşturmayı engelliyor; HTTP testi çalışmadı')
        with tempfile.TemporaryDirectory() as directory:
            with patch('reworkbench.webapp.Jobs', FakeJobs):
                app=Workbench(directory)
            server=LocalServer(('127.0.0.1',0),app,'fixture-token')
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            def request(method,path,body=None,headers=None):
                connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
                connection.request(method,path,body=body,headers=headers or {})
                response=connection.getresponse()
                data=response.read()
                result=response.status,dict(response.getheaders()),data
                connection.close()
                return result
            try:
                status,headers,body=request('GET','/')
                self.assertEqual(status,200)
                self.assertIn(b'RE Workbench',body)
                self.assertIn("script-src 'self'",headers['Content-Security-Policy'])
                self.assertEqual(request('GET','/api/history')[0],401)
                auth={'Authorization':'Bearer fixture-token','Origin':server.origin}
                self.assertEqual(request('POST','/api/cancel',b'{}',{**auth,'Origin':'https://evil.example','Content-Type':'application/json'})[0],403)
                payload=b'harmless http upload'
                status,_,body=request('POST','/api/analyze?mode=reverse',payload,{**auth,'Content-Type':'application/octet-stream','X-File-Name':'fixture.txt'})
                self.assertEqual(status,202)
                job_id=json.loads(body)['id']
                path,modules=app.jobs.submitted[0]
                app.publish('result',analyze(app.store,path,modules))
                status,headers,body=request('GET',f'/api/jobs/{job_id}/report?format=md',headers=auth)
                self.assertEqual(status,200)
                self.assertIn('attachment',headers['Content-Disposition'])
                self.assertIn(b'# RE Workbench',body)
                self.assertEqual(request('GET','/../../etc/passwd',headers=auth)[0],404)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                app.close()
