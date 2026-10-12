import json
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from ndp.nautobot import DEVICE_QUERY, NautobotError, graphql, http_post, token_from_env

TOKEN = "t0k3n-abc"
PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
              "http_proxy", "https_proxy", "all_proxy", "no_proxy")


class Handler(BaseHTTPRequestHandler):
    status = 200
    reply = b'{"data": {"devices": []}}'
    seen: list = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Handler.seen.append((self.path, dict(self.headers), json.loads(body)))
        self.send_response(Handler.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(Handler.reply)

    def log_message(self, *args):
        pass


def serve(httpd, scheme):
    Handler.status, Handler.reply, Handler.seen = 200, b'{"data": {"devices": []}}', []
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return f"{scheme}://127.0.0.1:{httpd.server_port}/"


@pytest.fixture(autouse=True)
def no_proxy_env(monkeypatch):
    for name in PROXY_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    yield serve(httpd, "http")
    httpd.shutdown()


@pytest.fixture
def tls_server(tmp_path):
    """HTTPS with a self-signed certificate, like a locally signed Nautobot."""
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl not installed")
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=nautobot.local", "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True,
    )
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    yield serve(httpd, "https")
    httpd.shutdown()


def test_graphql_posts_query_with_token(server):
    data = graphql(server, TOKEN, DEVICE_QUERY, {"roles": ["PE"]}, http_post(5))
    assert data == {"devices": []}
    path, headers, body = Handler.seen[0]
    assert path == "/api/graphql/"
    assert headers["Authorization"] == f"Token {TOKEN}"
    assert body == {"query": DEVICE_QUERY, "variables": {"roles": ["PE"]}}


def test_http_error_names_status_not_token(server):
    Handler.status, Handler.reply = 403, b'{"detail": "Invalid token."}'
    with pytest.raises(NautobotError, match="HTTP 403") as exc:
        graphql(server, TOKEN, DEVICE_QUERY, {}, http_post(5))
    assert TOKEN not in str(exc.value)


def test_unreachable():
    with pytest.raises(NautobotError, match="cannot reach Nautobot at http://127.0.0.1:9/api/graphql/"):
        graphql("http://127.0.0.1:9", TOKEN, DEVICE_QUERY, {}, http_post(2))


def test_self_signed_certificate_is_rejected_by_default(tls_server):
    with pytest.raises(NautobotError, match="certificate verify failed"):
        graphql(tls_server, TOKEN, DEVICE_QUERY, {}, http_post(5))


def test_self_signed_certificate_accepted_without_verify(tls_server):
    data = graphql(tls_server, TOKEN, DEVICE_QUERY, {}, http_post(5, verify_tls=False))
    assert data == {"devices": []}


def test_explicit_proxy_is_used(server):
    # a proxy receives the absolute URL; the test server plays the proxy
    graphql("http://nautobot.example", TOKEN, DEVICE_QUERY, {}, http_post(5, proxy=server))
    assert Handler.seen[0][0] == "http://nautobot.example/api/graphql/"


def test_environment_proxy_is_used(server, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", server)
    graphql("http://nautobot.example", TOKEN, DEVICE_QUERY, {}, http_post(5))
    assert Handler.seen[0][0] == "http://nautobot.example/api/graphql/"


def test_no_proxy_goes_direct(server, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")  # nothing listens there
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    graphql(server, TOKEN, DEVICE_QUERY, {}, http_post(5))
    assert Handler.seen[0][0] == "/api/graphql/"


@pytest.mark.parametrize("reply, message", [
    (b"<html>login</html>", "no JSON"),
    (b'{"errors": [{"message": "Unknown argument role"}]}', "Nautobot GraphQL: .*Unknown argument role"),
    (b'{"data": null}', "returned no data"),
])
def test_bad_replies(reply, message):
    with pytest.raises(NautobotError, match=message):
        graphql("https://nautobot.example", TOKEN, DEVICE_QUERY, {}, lambda url, body, headers: reply)


def test_token_from_env():
    assert token_from_env({"NAUTOBOT_TOKEN": " abc "}) == "abc"
    with pytest.raises(NautobotError, match="NAUTOBOT_TOKEN"):
        token_from_env({})
