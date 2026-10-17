import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest


class LabHTTP(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.requests.append(self.path)
        pages = {
            '/': '<html><head><title>PenPilot local lab</title></head><body><h1>Authorized test lab</h1><!-- public test comment --><a href="/docs/">Docs</a><a href="http://outside.invalid/">Outside</a><script src="/app.js"></script><form action="/login" method="post"></form>lab@example.invalid</body></html>',
            '/docs/': '<html><title>Documentation</title><a href="/docs/deeper/">Deep</a></html>',
            '/docs/deeper/': '<html><title>Depth two</title>controlled fixture</html>',
            '/app.js': '/* fixture only */',
            '/admin/': 'Private administrative area',
            '/robots.txt': 'Disallow: /admin/',
        }
        if self.path == '/redirect':
            self.send_response(302); self.send_header('Location', 'http://outside.invalid/'); body=b'redirect'
        elif self.path in pages:
            self.send_response(403 if self.path == '/admin/' else 200); body=pages[self.path].encode()
        else:
            self.send_response(404); body=b'Not found'
        self.send_header('Content-Type','text/html; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Set-Cookie', 'session=do-not-log')
        self.end_headers(); self.wfile.write(body)


@pytest.fixture
def lab_http():
    LabHTTP.requests=[]
    server=ThreadingHTTPServer(('127.0.0.1',0),LabHTTP)
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    yield server.server_port, LabHTTP.requests
    server.shutdown(); server.server_close(); thread.join()
