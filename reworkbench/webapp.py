"""Loopback-only browser workbench with authenticated, bounded local APIs."""

import argparse
import asyncio
import importlib.util
import json
import mimetypes
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from . import __version__
from .dynamic import Sandbox
from .engine import hex_page
from .jobs import Jobs
from .mcp_client import Config, MCP
from .storage import MAX_FILE, Store, markdown

MODES = {'static': ['strings', 'elf', 'metrics'],
         'reverse': ['strings', 'elf', 'metrics', 'disassembly']}
ASSETS = Path(__file__).with_name('web')
TERMINAL = {'completed', 'cancelled', 'error'}


class APIError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def filename(value):
    value = unquote(value)
    if not value or len(value.encode('utf-8')) > 240 or value in ('.', '..'):
        raise APIError('Geçerli bir dosya adı gerekli.')
    if '/' in value or '\\' in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise APIError('Dosya adı yol veya kontrol karakteri içeremez.')
    return value


def public_summary(result):
    modules = result.get('modules', {})
    binary = modules.get('elf', {})
    return {'file': result['file'], 'created_at': result.get('created_at'),
            'run_id': result.get('run_id'), 'format': result['identification']['format'],
            'description': result['identification'].get('description', {}).get('text', '')[:10000],
            'architecture': binary.get('architecture', '—'), 'bits': binary.get('bits', '—'),
            'abi': binary.get('abi', '—'), 'entry': binary.get('entry', '—'),
            'dependencies': binary.get('dependencies', [])[:1000],
            'build_notes': binary.get('build_notes', binary.get('raw', {}).get('build_notes', {})).get('text', '')[:20000],
            'modules': {k: {x: v[x] for x in ('status', 'reason', 'backend', 'limits', 'scope', 'note', 'truncated') if x in v} for k, v in modules.items()},
            'counts': {'strings': len(modules.get('strings', {}).get('rows', [])),
                       'symbols': len(binary.get('symbols', [])),
                       'sections': len(binary.get('sections', [])),
                       'disassembly': len(modules.get('disassembly', {}).get('rows', [])),
                       'indicators': len(result.get('indicators', []))},
            'observations': result.get('observations', []), 'metrics': modules.get('metrics', {})}


class Workbench:
    def __init__(self, root=None):
        self.store = Store(root)
        self.lock = threading.RLock()
        self.records = {}
        self.active = None
        self.uploading = False
        self.events = []
        self.jobs = Jobs(self.store.root, self.publish)
        self.mcp = None
        self.mcp_queue = queue.Queue(maxsize=10)
        self.mcp_thread = None
        self.mcp_state = {'state': 'disconnected', 'tools': [], 'message': 'Bağlı değil'}
        self.sandbox = Sandbox()
        self.dynamic_cancel = threading.Event()
        self.dynamic_thread = None
        self.dynamic_state = {'state': 'disabled', 'message': 'İsteğe bağlı · Onay olmadan çalışmaz.'}
        self.plans = {}
        self._restore_history()

    def _restore_history(self):
        paths = sorted((self.store.root / 'reports').glob('*/*.json'), key=lambda p: p.stat().st_mtime, reverse=True)[:12]
        for path in reversed(paths):
            try:
                if path.stat().st_size > 24 * 1024**2:
                    continue
                result = json.loads(path.read_text(encoding='utf-8'))
                self.records[result['run_id']] = {'id': result['run_id'], 'state': 'completed',
                    'progress': 100, 'mode': 'reverse' if 'disassembly' in result['modules'] else 'static',
                    'name': result['file']['name'], 'message': 'Tamamlandı', 'report': str(path),
                    'summary': public_summary(result)}
            except (OSError, ValueError, KeyError, TypeError):
                continue

    def publish(self, kind, data):
        with self.lock:
            self.events.append({'event': kind, 'time': time.strftime('%H:%M:%S')})
            self.events = self.events[-60:]
            if kind.startswith('mcp_'):
                if kind == 'mcp_ready':
                    self.mcp_state = {'state': 'connected', **data, 'message': 'Bağlandı'}
                elif kind == 'mcp_result':
                    self.mcp_state['result'] = data
                    self.mcp_state['busy'] = False
                elif kind == 'mcp_error':
                    self.mcp_state.update(message=data, busy=False, error=data)
                elif kind == 'mcp_closed':
                    self.mcp_state.update(state='disconnected', tools=[], busy=False)
                return
            if not self.active or self.active not in self.records:
                return
            item = self.records[self.active]
            if kind == 'progress':
                item.update(progress=data[0], message=data[1], state='running')
            elif kind == 'result':
                digest, run_id = data['file']['hashes']['sha256'], data['run_id']
                path = self.store.root / 'reports' / digest / (run_id + '.json')
                item.update(state='completed', progress=100, message='Analiz tamamlandı',
                            report=str(path), summary=public_summary(data))
            elif kind in ('error', 'cancelled'):
                item.update(state=kind, message=data)
            if item['state'] in TERMINAL:
                shutil.rmtree(item.pop('upload_dir', ''), ignore_errors=True)
                self.active = None

    def upload(self, stream, length, name, mode):
        if mode not in MODES:
            raise APIError('Geçersiz analiz modu.')
        name = filename(name)
        if not 0 <= length <= MAX_FILE:
            raise APIError('Dosya boyutu en fazla 64 MiB olabilir.', 413)
        with self.lock:
            if self.active or self.uploading or (self.dynamic_thread and self.dynamic_thread.is_alive()):
                raise APIError('Etkin analiz bitene kadar bekleyin veya iptal edin.', 409)
            self.uploading = True
        directory = None
        try:
            self.store.capacity()
            job_id = uuid.uuid4().hex
            directory = self.store.root / 'uploads' / job_id
            directory.mkdir(parents=True, mode=0o700)
            directory.parent.chmod(0o700)
            path = directory / name
            remaining = length
            with path.open('xb') as out:
                path.chmod(0o600)
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        raise APIError('Dosya aktarımı yarım kaldı.')
                    out.write(chunk)
                    remaining -= len(chunk)
            with self.lock:
                if len(self.records) >= 16:
                    del self.records[next(iter(self.records))]
                self.records[job_id] = {'id': job_id, 'name': name, 'mode': mode,
                    'state': 'queued', 'progress': 0, 'message': 'Kuyrukta',
                    'upload_dir': str(directory)}
                self.active = job_id
                try:
                    self.jobs.submit(path, MODES[mode])
                except Exception:
                    self.active = None
                    self.records.pop(job_id, None)
                    raise
            directory = None
            return {'id': job_id}
        finally:
            with self.lock:
                self.uploading = False
            if directory:
                shutil.rmtree(directory, ignore_errors=True)

    def record(self, job_id):
        with self.lock:
            if job_id not in self.records:
                raise APIError('Analiz bulunamadı.', 404)
            return dict(self.records[job_id])

    def report(self, job_id):
        item = self.record(job_id)
        if item['state'] != 'completed':
            raise APIError('Analiz henüz tamamlanmadı.', 409)
        return json.loads(Path(item['report']).read_text(encoding='utf-8'))

    def view(self, job_id, query):
        result = self.report(job_id)
        tab = query.get('tab', ['strings'])[0]
        search = query.get('q', [''])[0][:300].casefold()
        kind = query.get('kind', [''])[0]
        try:
            offset = max(0, int(query.get('offset', ['0'])[0]))
            limit = min(200, max(1, int(query.get('limit', ['100'])[0])))
        except ValueError:
            raise APIError('Geçersiz sayfa aralığı.') from None
        modules = result['modules']
        binary = modules.get('elf', {})
        tables = {'strings': modules.get('strings', {}).get('rows', []),
                  'symbols': binary.get('symbols', []), 'sections': binary.get('sections', []),
                  'segments': binary.get('segments', []),
                  'disassembly': modules.get('disassembly', {}).get('rows', []),
                  'indicators': result.get('indicators', [])}
        if tab == 'hex':
            try:
                position = int(query.get('address', ['0'])[0], 0)
            except ValueError:
                raise APIError('Adres için 0x1000 veya 4096 gibi bir dosya ofseti girin.') from None
            if not 0 <= position <= result['file']['size']:
                raise APIError('Ofset dosya boyutu dışında.')
            path = self.store.root / 'quarantine' / result['file']['hashes']['sha256']
            return {'text': hex_page(path, position), 'address': position, 'size': result['file']['size']}
        if tab not in tables:
            raise APIError('Bilinmeyen sonuç görünümü.')
        rows = tables[tab]
        if search:
            rows = [row for row in rows if search in json.dumps(row, ensure_ascii=False).casefold()]
        if kind:
            rows = [row for row in rows if kind in (row.get('kind'), row.get('encoding'), row.get('direction'), row.get('type'))]
        return {'rows': rows[offset:offset + limit], 'total': len(rows), 'offset': offset,
                'limit': limit, 'tab': tab}

    def connect_mcp(self):
        with self.lock:
            if self.mcp_thread and self.mcp_thread.is_alive():
                raise APIError('MCP bağlantısı zaten açık veya kuruluyor.', 409)
            try:
                self.mcp = MCP(Config.load(os.environ.get('REWB_MCP_CONFIG') or None))
            except (ValueError, OSError, TypeError):
                raise APIError('MCP yapılandırılmamış veya geçersiz. REWB_MCP_URL / REWB_MCP_CONFIG ayarlarını kontrol edin.') from None
            self.mcp_queue = queue.Queue(maxsize=10)
            self.mcp_state = {'state': 'connecting', 'tools': [], 'message': 'Bağlanıyor…', 'url': self.mcp.config.url}
            self.mcp_thread = threading.Thread(target=lambda: asyncio.run(self.mcp.serve(self.mcp_queue, self.publish)), daemon=True)
            self.mcp_thread.start()
        return {'state': 'connecting'}

    def action(self, path, data):
        if path == '/api/cancel':
            self.jobs.cancel()
            self.dynamic_cancel.set()
            return {'message': 'İptal istendi.'}
        if path == '/api/mcp/connect':
            return self.connect_mcp()
        if path == '/api/mcp/disconnect':
            if self.mcp:
                self.mcp.pending.clear()
                self._enqueue_mcp(None)
            return {'message': 'Bağlantı kapatılıyor.'}
        if path == '/api/mcp/refresh':
            self._require_mcp()
            self._enqueue_mcp(('refresh', None))
            return {'message': 'Araçlar yenileniyor.'}
        if path == '/api/mcp/prepare':
            self._require_mcp()
            if not isinstance(data.get('name'), str) or not isinstance(data.get('arguments'), dict):
                raise APIError('Araç adı ve JSON nesnesi gerekli.')
            try:
                ticket, payload = self.mcp.prepare(data['name'], data['arguments'])
            except Exception:
                raise APIError('Parametreler geçersiz veya aracın şeması desteklenmiyor.') from None
            return {'ticket': ticket, 'payload': payload, 'destination': self.mcp.config.url}
        if path == '/api/mcp/call':
            self._require_mcp()
            if data.get('confirmed') is not True or data.get('ticket') not in self.mcp.pending:
                raise APIError('Gösterilen MCP çağrısı için açık onay gerekli.', 403)
            if self.mcp_state.get('busy'):
                raise APIError('Önceki MCP çağrısı sürüyor.', 409)
            self.mcp_state.update(busy=True, result=None, error=None)
            self._enqueue_mcp(('call', data['ticket']))
            return {'message': 'Onaylanan çağrı gönderildi.'}
        if path == '/api/dynamic/prepare':
            if self.active:
                raise APIError('Önce statik analizin bitmesini bekleyin.', 409)
            result = self.report(data.get('id'))
            path = self.store.root / 'quarantine' / result['file']['hashes']['sha256']
            try:
                self.sandbox.pending.clear()
                ticket, plan = self.sandbox.prepare(path)
            except ValueError as error:
                raise APIError(str(error)) from None
            self.plans = {ticket: {'id': data['id'], 'deadline': time.monotonic() + 300}}
            return {'ticket': ticket, 'plan': plan}
        if path == '/api/dynamic/run':
            ticket = data.get('ticket')
            plan = self.plans.pop(ticket, None)
            if data.get('confirmed') is not True or not plan or time.monotonic() > plan['deadline']:
                raise APIError('Geçerli dinamik analiz planı ve açık onay gerekli.', 403)
            with self.lock:
                if self.active or (self.dynamic_thread and self.dynamic_thread.is_alive()):
                    raise APIError('Başka bir analiz etkin.', 409)
                self.dynamic_cancel.clear()
                self.dynamic_state = {'state': 'running', 'id': plan['id'], 'message': 'Yalıtılmış analiz çalışıyor…'}
                def execute():
                    try:
                        output = self.sandbox.execute(ticket, self.dynamic_cancel)
                        with self.lock:
                            self.dynamic_state.update(state='completed', message='Çalıştırma sona erdi', result=output)
                    except Exception:
                        with self.lock:
                            self.dynamic_state.update(state='error', message='Dinamik analiz durduruldu/başlatılamadı; Podman ortamını ve temizliği kontrol edin.')
                self.dynamic_thread = threading.Thread(target=execute, daemon=False)
                self.dynamic_thread.start()
            return {'state': 'running'}
        raise APIError('İşlem bulunamadı.', 404)

    def _require_mcp(self):
        if not self.mcp or self.mcp_state.get('state') != 'connected':
            raise APIError('Önce MCP sunucusuna bağlanın.', 409)

    def _enqueue_mcp(self, item):
        try:
            self.mcp_queue.put_nowait(item)
        except queue.Full:
            raise APIError('MCP kuyruğu dolu.', 409) from None

    def get(self, path, query):
        if path == '/api/status':
            return {'version': __version__, 'active': self.active, 'events': self.events,
                    'tools': {name: bool(shutil.which(name)) for name in ('file', 'readelf', 'objdump', 'podman')},
                    'packages': {name: importlib.util.find_spec(name) is not None for name in ('capstone', 'elftools', 'mcp')},
                    'mcp': self.mcp_state.get('state'), 'dynamic': self.dynamic_state.get('state')}
        if path == '/api/history':
            with self.lock:
                return {'jobs': [{k: v for k, v in item.items() if k not in ('upload_dir', 'report')}
                                  for item in reversed(list(self.records.values()))]}
        if path == '/api/mcp':
            with self.lock:
                return dict(self.mcp_state)
        if path == '/api/dynamic':
            with self.lock:
                return dict(self.dynamic_state)
        match = re.fullmatch(r'/api/jobs/([a-f0-9]{32})(?:/(view|report))?', path)
        if match:
            job_id, action = match.groups()
            if action == 'view':
                return self.view(job_id, query)
            if action == 'report':
                return self.report(job_id)
            return {k: v for k, v in self.record(job_id).items() if k not in ('upload_dir', 'report')}
        raise APIError('Kaynak bulunamadı.', 404)

    def close(self):
        self.jobs.close()
        self.dynamic_cancel.set()
        if self.mcp:
            try:
                self.mcp_queue.put_nowait(None)
            except queue.Full:
                pass


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, app, token):
        if address[0] != '127.0.0.1':
            raise ValueError('Sunucu yalnızca 127.0.0.1 üzerinde çalışabilir.')
        self.app, self.token = app, token
        super().__init__(address, Handler)
        self.origin = f'http://127.0.0.1:{self.server_port}'
        self.slots = threading.BoundedSemaphore(8)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def authorize(headers, origin, token, mutation=False):
    if headers.get('Host') != urlsplit(origin).netloc:
        raise APIError('Geçersiz Host başlığı.', 403)
    if headers.get('Origin') not in (None, origin) or (mutation and headers.get('Origin') != origin):
        raise APIError('Yalnızca aynı kaynaktan gelen istekler kabul edilir.', 403)
    if headers.get('Sec-Fetch-Site') in ('cross-site', 'same-site'):
        raise APIError('Siteler arası erişim kapalı.', 403)
    provided = headers.get('Authorization', '')
    if not secrets.compare_digest(provided.encode(), ('Bearer ' + token).encode()):
        raise APIError('Oturum doğrulanamadı. Terminaldeki tam bağlantıyı açın.', 401)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, *_):
        pass  # No tokens, sample names, payloads or contents in access logs.

    def respond(self, status, body, content_type='application/json; charset=utf-8', attachment=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode('utf-8')
        elif isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        if attachment:
            self.send_header('Content-Disposition', f'attachment; filename="{attachment}"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            parsed = urlsplit(self.path)
            if self.headers.get('Host') != urlsplit(self.server.origin).netloc:
                raise APIError('Geçersiz Host başlığı.', 403)
            assets = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css', '/favicon.svg': 'favicon.svg'}
            if parsed.path in assets:
                target = ASSETS / assets[parsed.path]
                content_type = mimetypes.guess_type(str(target))[0] or 'application/octet-stream'
                self.respond(200, target.read_bytes(), content_type + '; charset=utf-8')
                return
            authorize(self.headers, self.server.origin, self.server.token)
            query = parse_qs(parsed.query)
            data = self.server.app.get(parsed.path, query)
            if parsed.path.endswith('/report'):
                if query.get('format', ['json'])[0] == 'md':
                    self.respond(200, markdown(data), 'text/markdown; charset=utf-8', 'rewb-report.md')
                else:
                    self.respond(200, data, attachment='rewb-report.json')
                return
            self.respond(200, data)
        except APIError as error:
            self.respond(error.status, {'error': str(error)})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.respond(500, {'error': 'İşlem tamamlanamadı; yerel dosyaları ve kaynak sınırlarını kontrol edin.'})

    def do_POST(self):
        try:
            authorize(self.headers, self.server.origin, self.server.token, mutation=True)
            if self.headers.get('Transfer-Encoding'):
                raise APIError('Parçalı HTTP aktarımı desteklenmiyor.')
            raw_length = self.headers.get('Content-Length', '')
            if not raw_length.isdecimal():
                raise APIError('Geçerli içerik uzunluğu gerekli.')
            length = int(raw_length)
            parsed = urlsplit(self.path)
            if parsed.path == '/api/analyze':
                if self.headers.get('Content-Type') != 'application/octet-stream':
                    raise APIError('İkili dosya gövdesi gerekli.')
                query = parse_qs(parsed.query)
                data = self.server.app.upload(self.rfile, length, self.headers.get('X-File-Name', ''), query.get('mode', ['static'])[0])
                self.respond(202, data)
                return
            if length > 131072:
                raise APIError('İstek boyutu sınırı.', 413)
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                raise APIError('JSON gövdesi gerekli.')
            try:
                raw = self.rfile.read(length)
                data = json.loads(raw)
            except (ValueError, UnicodeError):
                raise APIError('Geçersiz JSON.') from None
            if not isinstance(data, dict):
                raise APIError('JSON nesnesi gerekli.')
            self.respond(200, self.server.app.action(parsed.path, data))
        except APIError as error:
            self.respond(error.status, {'error': str(error)})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.respond(500, {'error': 'İşlem tamamlanamadı. Yapılandırmayı ve kaynak sınırlarını kontrol edin.'})


def main():
    parser = argparse.ArgumentParser(description='RE Workbench · Yerel tarayıcı arayüzü')
    parser.add_argument('--port', type=int, default=8780)
    parser.add_argument('--store', type=Path)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('Port 1024–65535 arasında olmalı.')
    app = Workbench(args.store)
    server = None
    try:
        server = LocalServer(('127.0.0.1', args.port), app, secrets.token_urlsafe(32))
        url = server.origin + '/#token=' + server.token
        print('\nRE Workbench hazır. Bu kişisel oturum bağlantısını tarayıcıda açın:\n' + url + '\nDurdurmak için Ctrl+C.\n', flush=True)
        if not args.no_browser:
            import webbrowser
            threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
        server.serve_forever(poll_interval=0.2)
    except OSError:
        parser.exit(1, 'Yerel sunucu açılamadı. Port kullanımını veya ortamın soket izinlerini kontrol edin.\n')
    except KeyboardInterrupt:
        print('\nRE Workbench durduruluyor.')
    finally:
        app.close()
        if server:
            server.server_close()


if __name__ == '__main__':
    main()
