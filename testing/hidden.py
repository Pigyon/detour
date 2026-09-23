"""An endpoint with one redirect parameter that nothing links to.

--deep exists to find a name no crawl, archive or corpus entry would suggest,
so the check needs a server where exactly one unlinked name is honoured and
every other guess is a plain 200.
"""
import http.server, socketserver, sys, urllib.parse

SECRET = "returnTo"


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if SECRET in q:
            self.send_response(302)
            self.send_header("Location", q[SECRET][0])
        else:
            self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
