"""Small deterministic HTTP lab for local PenPilot validation, bound to loopback."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests'))
from conftest import LabHTTP
from http.server import ThreadingHTTPServer
print('Controlled HTTP fixture: http://127.0.0.1:18081', flush=True)
ThreadingHTTPServer(('127.0.0.1', 18081), LabHTTP).serve_forever()
