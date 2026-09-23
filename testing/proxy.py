"""A logging forward proxy, so a run can be checked by what it actually sent.

Every request is written to the log as "host<TAB>auth<TAB>cookie<TAB>url"
before it is forwarded, which is what the scope and credential invariants are
asserted against.
"""
import http.server, http.client, socketserver, sys, urllib.parse

LOG = open(sys.argv[2], "w", buffering=1)


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.proxy("GET")

    def do_POST(self):
        self.proxy("POST")

    def do_HEAD(self):
        self.proxy("HEAD")

    def proxy(self, method):
        u = urllib.parse.urlsplit(self.path)
        LOG.write("%s\t%s\t%s\t%s\n" % (
            u.hostname or "?",
            self.headers.get("Authorization", "-"),
            self.headers.get("Cookie", "-"),
            self.path))
        if not u.hostname:
            self.send_error(400)
            return
        try:
            c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=5)
            path = urllib.parse.urlunsplit(("", "", u.path or "/", u.query, ""))
            hdrs = {k: v for k, v in self.headers.items()
                    if k.lower() not in ("proxy-connection", "connection")}
            c.request(method, path, headers=hdrs)
            r = c.getresponse()
            body = r.read()
        except Exception:
            self.send_error(502)
            return
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() in ("transfer-encoding", "connection", "content-length"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(body)

    def log_message(self, *a):
        pass


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
