"""Local boundary test: Pages can read only existing bounded relay routes."""
import importlib.util
import json
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

spec = importlib.util.spec_from_file_location('relay', Path(__file__).resolve().parents[1] / 'serve.py')
assert spec is not None and spec.loader is not None
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class PagesCORS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), relay.make_handler(
            {}, 'relay.test', 'https://relay.test', 'http://127.0.0.1:1',
            chain_upstreams={1: 'http://127.0.0.1:1', 8453: 'http://127.0.0.1:1', 84532: 'http://127.0.0.1:1'}))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method, path='/rpc', origin=relay.PAGES_ORIGIN, body=None, **extra):
        connection = HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        headers = {'Host': 'relay.test', 'Origin': origin, **extra}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_exact_preflight(self):
        for path in ['/rpc', '/rpc/1', '/rpc/8453', '/rpc/84532']:
            code, headers, _ = self.request('OPTIONS', path,
                **{'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type'})
            self.assertEqual(code, 204)
            self.assertEqual(headers['Access-Control-Allow-Origin'], relay.PAGES_ORIGIN)
            self.assertNotIn('Access-Control-Allow-Credentials', headers)

    def test_reject_other_origins_routes_headers_and_methods(self):
        for values in [dict(origin='https://evil.test'), dict(origin=relay.PAGES_ORIGIN+'/p256-signer-web/'),
                       dict(path='/config.json'), dict(path='/rpc?x=1'), dict(path='//rpc')]:
            code, _, _ = self.request('OPTIONS', **values,
                **{'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type'})
            self.assertEqual(code, 403)
        self.assertEqual(self.request('OPTIONS', **{'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'authorization'})[0], 403)

    def test_no_sign_or_send_and_no_config_cors(self):
        for method in ['eth_sendTransaction', 'eth_sendRawTransaction', 'personal_sign', 'eth_signTypedData_v4']:
            code, headers, _ = self.request('POST', body=json.dumps({'jsonrpc': '2.0', 'id': 1,
                                                                    'method': method, 'params': []}))
            self.assertEqual(code, 403)
            self.assertEqual(headers['Access-Control-Allow-Origin'], relay.PAGES_ORIGIN)
        code, headers, _ = self.request('GET', '/config.json')
        self.assertEqual(code, 403)
        self.assertNotIn('Access-Control-Allow-Origin', headers)


if __name__ == '__main__':
    unittest.main()
