"""Read-only import for mitmdump -n -r. Never replay flows."""
from mitmproxy import ctx
from penpilot.intel import IntelStore


class ImportFlows:
    def load(self,loader):loader.add_option('penpilot_run',str,'','PenPilot case directory')
    def response(self,flow):
        store=IntelStore(ctx.options.penpilot_run)
        body=flow.response.get_text(strict=False) or ''
        entry=dict(request=dict(url=flow.request.pretty_url,method=flow.request.method,headers=dict(flow.request.headers),postData=dict(text=flow.request.get_text(strict=False) or '')),response=dict(status=flow.response.status_code,headers=dict(flow.response.headers),content=dict(text=body,size=len(flow.response.raw_content or b''),mimeType=flow.response.headers.get('content-type',''))))
        store.put(store.traffic([entry],'mitm-flow:'+flow.id))


addons=[ImportFlows()]
