import base64
import http.client
import json
import os
import queue
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY = bytes(range(32))
UPSTREAM_REQUESTS = queue.Queue()


class PlaintextUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self.handle_payload()

    def do_HEAD(self):
        self.handle_payload(head_only=True)

    def handle_payload(self, head_only=False):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        UPSTREAM_REQUESTS.put(body)
        status = int(self.headers.get("X-Upstream-Status", "200"))
        if status == 204:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if self.headers.get("X-Upstream-Empty") == "1":
            response = b""
        else:
            response = json.dumps({
                "received": json.loads(body) if body else None,
                "status": status,
            }, separators=(",", ":")).encode()

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        if not head_only:
            for offset in range(0, len(response), 4096):
                self.wfile.write(response[offset:offset + 4096])
                self.wfile.flush()

    def log_message(self, format, *args):
        pass


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class NginxRoundTripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        nginx = os.environ.get("NGINX_BIN") or shutil.which("nginx")
        module = os.environ.get("PAYLOADSHIELD_MODULE")
        if not nginx or not module:
            raise unittest.SkipTest(
                "Set NGINX_BIN and PAYLOADSHIELD_MODULE to run integration tests"
            )

        cls.temp = tempfile.TemporaryDirectory(prefix="payloadshield-it-")
        cls.root = Path(cls.temp.name)
        cls.nginx_port = free_port()
        cls.upstream_port = free_port()
        cls.key_path = cls.root / "symmetric.key"
        cls.key_path.write_bytes(KEY)
        try:
            cls.key_path.chmod(0o600)
        except OSError:
            pass

        cls.upstream = ThreadingHTTPServer(
            ("127.0.0.1", cls.upstream_port), PlaintextUpstream
        )
        cls.upstream_thread = threading.Thread(
            target=cls.upstream.serve_forever, daemon=True
        )
        cls.upstream_thread.start()

        cls.config = cls.root / "nginx.conf"
        cls.config.write_text(
            f'''load_module {Path(module).resolve()};
pid {cls.root / "nginx.pid"};
error_log stderr notice;
events {{ worker_connections 64; }}
http {{
    gzip on;
    gzip_min_length 1;
    gzip_types application/json;
    client_body_temp_path {cls.root / "client_temp"};
    proxy_temp_path {cls.root / "proxy_temp"};
    client_max_body_size 24m;
    client_body_buffer_size 1k;
    upstream test_backend {{ server 127.0.0.1:{cls.upstream_port}; }}
    server {{
        listen 127.0.0.1:{cls.nginx_port};
        location / {{
            gzip off;
            payloadshield on;
            payloadshield_algorithm aes-gcm-256;
            payloadshield_key {cls.key_path};
            payloadshield_max_body_size 10m;
            payloadshield_buffer_response on;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
            proxy_pass http://test_backend;
        }}
    }}
}}
''',
            encoding="utf-8",
        )

        subprocess.run(
            [nginx, "-t", "-p", f"{cls.root}/", "-c", str(cls.config)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        cls.nginx = subprocess.Popen(
            [nginx, "-p", f"{cls.root}/", "-c", str(cls.config),
             "-g", "daemon off;"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if cls.nginx.poll() is not None:
                raise RuntimeError("Nginx exited during integration test startup")
            try:
                with socket.create_connection(("127.0.0.1", cls.nginx_port), 0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("Nginx did not start before timeout")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "nginx"):
            cls.nginx.terminate()
            try:
                cls.nginx.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.nginx.kill()
                cls.nginx.wait()
        if hasattr(cls, "upstream"):
            cls.upstream.shutdown()
            cls.upstream.server_close()
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def test_nginx_t_rejects_unknown_algorithm_and_missing_key(self):
        nginx = os.environ.get("NGINX_BIN") or shutil.which("nginx")
        original = self.config.read_text(encoding="utf-8")
        invalid_pem = self.root / "invalid-private.pem"
        invalid_pem.write_text("not a PEM key", encoding="ascii")
        invalid_configs = (
            original.replace("payloadshield_algorithm aes-gcm-256;",
                             "payloadshield_algorithm unknown;"),
            original.replace(str(self.key_path), str(self.root / "missing.key")),
            original.replace(
                "payloadshield_algorithm aes-gcm-256;",
                "payloadshield_algorithm rsa-hybrid;",
            ).replace(
                f"payloadshield_key {self.key_path};",
                f"payloadshield_private_key {invalid_pem};\n"
                f"            payloadshield_public_key {invalid_pem};",
            ),
        )
        for index, config_text in enumerate(invalid_configs):
            with self.subTest(index=index):
                candidate = self.root / f"invalid-{index}.conf"
                candidate.write_text(config_text, encoding="utf-8")
                result = subprocess.run(
                    [nginx, "-t", "-p", f"{self.root}/", "-c", str(candidate)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)

    @staticmethod
    def encrypt(value):
        plaintext = json.dumps(value, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        ciphertext_and_tag = AESGCM(KEY).encrypt(nonce, plaintext, None)
        encoded = base64.b64encode(nonce + ciphertext_and_tag).decode()
        return json.dumps({"encrypted": encoded}, separators=(",", ":")).encode(), plaintext

    @staticmethod
    def decrypt(body):
        envelope = json.loads(body)
        raw = base64.b64decode(envelope["encrypted"], validate=True)
        return AESGCM(KEY).decrypt(raw[:12], raw[12:], None)

    def post(self, value, headers=None, encode_chunked=False):
        body, plaintext = self.encrypt(value)
        connection = http.client.HTTPConnection("127.0.0.1", self.nginx_port,
                                                timeout=15)
        connection.request("POST", "/echo", body=body, headers=headers or {},
                           encode_chunked=encode_chunked)
        response = connection.getresponse()
        result = response.read()
        status = response.status
        connection.close()
        return status, result, plaintext

    def test_encrypted_request_upstream_plaintext_and_encrypted_response(self):
        value = {"secret": "not visible in upstream wire", "n": 17}
        status, body, plaintext = self.post(value)
        self.assertEqual(status, 200)
        decoded = json.loads(self.decrypt(body))
        self.assertEqual(decoded["received"], value)
        self.assertEqual(UPSTREAM_REQUESTS.get(timeout=2), plaintext)

    def test_upstream_statuses_are_preserved_and_payloads_encrypted(self):
        for status in (200, 201, 400, 401, 404, 500):
            with self.subTest(status=status):
                actual, body, _ = self.post({"status": status}, {
                    "X-Upstream-Status": str(status),
                })
                self.assertEqual(actual, status)
                self.assertEqual(json.loads(self.decrypt(body))["status"], status)

    def test_chunked_request_and_large_multichunk_response(self):
        value = {"blob": "z" * (256 * 1024)}
        status, body, plaintext = self.post(value, encode_chunked=True)
        self.assertEqual(status, 200)
        self.assertEqual(UPSTREAM_REQUESTS.get(timeout=2), plaintext)
        self.assertEqual(json.loads(self.decrypt(body))["received"], value)

    def test_empty_response_is_encrypted(self):
        status, body, _ = self.post({}, {"X-Upstream-Empty": "1"})
        self.assertEqual(status, 200)
        self.assertEqual(self.decrypt(body), b"")

    def test_gzip_negotiation_does_not_compress_ciphertext(self):
        value = {"gzip": "disabled around encrypted payloads"}
        request_body, _ = self.encrypt(value)
        connection = http.client.HTTPConnection("127.0.0.1", self.nginx_port,
                                                timeout=10)
        connection.request("POST", "/echo", body=request_body,
                           headers={"Accept-Encoding": "gzip"})
        response = connection.getresponse()
        body = response.read()
        self.assertIsNone(response.getheader("Content-Encoding"))
        self.assertEqual(json.loads(self.decrypt(body))["received"], value)
        connection.close()

    def test_204_has_no_payload_and_bodyless_head_bypasses(self):
        status, body, _ = self.post({}, {"X-Upstream-Status": "204"})
        self.assertEqual(status, 204)
        self.assertEqual(body, b"")

        connection = http.client.HTTPConnection("127.0.0.1", self.nginx_port,
                                                timeout=10)
        connection.request("HEAD", "/echo")
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"")
        connection.close()

    def test_malformed_request_is_rejected_before_upstream(self):
        before = UPSTREAM_REQUESTS.qsize()
        connection = http.client.HTTPConnection("127.0.0.1", self.nginx_port,
                                                timeout=10)
        connection.request("POST", "/echo", body=b'{"encrypted":"bad"}',
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 400)
        connection.close()
        self.assertEqual(UPSTREAM_REQUESTS.qsize(), before)


if __name__ == "__main__":
    unittest.main()