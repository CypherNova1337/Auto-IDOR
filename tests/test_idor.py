"""Unit and end-to-end tests for IDOR-Auto.

Run with:  python -m unittest discover -s tests
The end-to-end test spins up an in-process mock API, so no network is needed.
"""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from auto_idor.analyze import classify, detect_identifiers, parse_raw_request
from auto_idor.config import scan_from_dict
from auto_idor.engine import Engine
from auto_idor.http import Response
from auto_idor.mutate import encode, resolve_encodings
from auto_idor.oracle import Confidence, Oracle, Verdict


def r(status, body):
    return Response(status=status, body=body, length=len(body), elapsed_ms=1)


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.oracle = Oracle()

    def test_vulnerable_via_similarity(self):
        owner = r(200, '{"owner":"bob","amount":300}')
        attacker = r(200, '{"owner":"bob","amount":300}')
        denied = r(401, '{"error":"auth required"}')
        j = self.oracle.evaluate("2001", owner, attacker, denied)
        self.assertEqual(j.verdict, Verdict.VULNERABLE)
        self.assertEqual(j.confidence, Confidence.HIGH)

    def test_vulnerable_via_canary(self):
        owner = r(200, '{"email":"bob@corp.example","x":1}')
        attacker = r(200, '{"email":"bob@corp.example","x":1}')
        denied = r(401, "nope")
        j = self.oracle.evaluate("2001", owner, attacker, denied,
                                 victim_secrets=["bob@corp.example"])
        self.assertEqual(j.verdict, Verdict.VULNERABLE)
        self.assertIn("bob@corp.example", j.leaked_secrets)

    def test_secure_endpoint_denied(self):
        owner = r(200, '{"owner":"bob"}')
        attacker = r(403, '{"error":"forbidden"}')
        denied = r(401, "nope")
        j = self.oracle.evaluate("2001", owner, attacker, denied)
        self.assertEqual(j.verdict, Verdict.NOT_VULNERABLE)

    def test_public_endpoint_not_idor(self):
        # Everyone (including anon) sees the same body -> public, not IDOR.
        body = '{"id":"2001","note":"public"}'
        j = self.oracle.evaluate("2001", r(200, body), r(200, body), r(200, body))
        self.assertEqual(j.verdict, Verdict.NOT_VULNERABLE)
        self.assertIn("public", j.reason)

    def test_canary_ignored_when_public(self):
        # Secret is present in the anon baseline too -> public exposure, not IDOR.
        body = '{"email":"bob@corp.example"}'
        j = self.oracle.evaluate("2001", r(200, body), r(200, body), r(200, body),
                                 victim_secrets=["bob@corp.example"])
        self.assertEqual(j.verdict, Verdict.NOT_VULNERABLE)

    def test_inconclusive_when_owner_fails(self):
        owner = r(500, "boom")
        j = self.oracle.evaluate("2001", owner, r(200, "x"), r(401, "y"))
        self.assertEqual(j.verdict, Verdict.INCONCLUSIVE)


class AnalyzeTests(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify("12345"), "int")
        self.assertEqual(classify("550e8400-e29b-41d4-a716-446655440000"), "uuid")
        self.assertEqual(classify("507f1f77bcf86cd799439011"), "objectid")
        self.assertEqual(classify("dXNlcjEyMw"), "base64")  # base64url of "user123"
        # plain lowercase words are not identifiers
        self.assertIsNone(classify("invoices"))
        self.assertIsNone(classify("customer"))
        self.assertIsNone(classify(""))

    def test_detect_ranks_path_id(self):
        base, tpl = parse_raw_request(
            "GET /api/v1/invoices/2001 HTTP/1.1\nHost: h\n\n", auto_mark=False
        )
        cands = detect_identifiers(tpl)
        self.assertTrue(cands)
        self.assertEqual(cands[0].value, "2001")

    def test_parse_raw_json_body(self):
        raw = (
            "POST /graphql HTTP/1.1\nHost: h\nContent-Type: application/json\n\n"
            '{"variables": {"id": "abc123def"}}'
        )
        base, tpl = parse_raw_request(raw, auto_mark=False)
        self.assertEqual(tpl.method, "POST")
        self.assertEqual(tpl.json_body["variables"]["id"], "abc123def")

    def test_auto_mark_places_token(self):
        base, tpl = parse_raw_request("GET /users/2001 HTTP/1.1\nHost: h\n\n")
        self.assertIn("{id}", tpl.path)


class MutateTests(unittest.TestCase):
    def test_encodings(self):
        self.assertEqual(encode("2001", "raw"), "2001")
        self.assertEqual(encode("2001", "base64"), "MjAwMQ==")
        self.assertEqual(encode("2001", "hex"), "32303031")

    def test_resolve_unknown(self):
        with self.assertRaises(KeyError):
            resolve_encodings(["nope"])


# -- end-to-end against an in-process mock API ----------------------------

class _MockHandler(BaseHTTPRequestHandler):
    INVOICES = {"1001": {"owner": "alice"}, "2001": {"owner": "bob"}}

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parts = self.path.strip("/").split("/")
        auth = self.headers.get("Authorization", "")
        if parts[:3] == ["api", "v1", "invoices"] and len(parts) == 4:
            if not auth.startswith("Bearer "):
                return self._send(401, {"error": "auth required"})
            inv = self.INVOICES.get(parts[3])
            return self._send(200, inv) if inv else self._send(404, {})
        return self._send(404, {})


class EngineE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_detects_idor(self):
        scan = scan_from_dict({
            "base_url": f"http://127.0.0.1:{self.port}",
            "threads": 2,
            "identities": [
                {"name": "alice", "headers": {"Authorization": "Bearer ALICE"}, "owns": ["1001"]},
                {"name": "bob", "headers": {"Authorization": "Bearer BOB"}, "owns": ["2001"]},
            ],
            "rules": [
                {"name": "inv", "request": {"method": "GET", "path": "/api/v1/invoices/{id}"}},
            ],
        })
        findings = Engine(scan).run()
        verdicts = {(f.attacker, f.victim, f.object_id): f.judgement.verdict for f in findings}
        self.assertEqual(verdicts[("alice", "bob", "2001")], Verdict.VULNERABLE)
        self.assertEqual(verdicts[("bob", "alice", "1001")], Verdict.VULNERABLE)


if __name__ == "__main__":
    unittest.main()
