"""A server that answers badly on purpose, for the retry and parser checks.

  /429   always rate limited, which detour should retry
  /403   always forbidden, which is terminal and should not be retried
  /slow  never answers, for the timeout check
  /nasty a hostile Refresh header and malformed meta tags

Request counts per path are printed on SIGTERM.
"""
import http.server, socketserver, signal, sys, time, collections

COUNT = collections.Counter()

NASTY = (b'<meta http-equiv="refresh" content="0;url=">'
         b'<meta http-equiv=refresh content=";;;;">'
         b'<meta http-equiv="REFRESH" CONTENT="0 ; URL = \x00\x01 ">'
         b'<!-- <meta http-equiv="refresh" content="0;url=https://x/"> -->'
         b'<script><meta http-equiv="refresh" content="0;url=https://y/"></script>'
         b'<meta http-equiv="refresh" content="')


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        p = self.path.split("?")[0]
        COUNT[p] += 1
        if p == "/slow":
            time.sleep(60)
            return
        if p == "/429":
            self.send_response(429)
        elif p == "/403":
            self.send_response(403)
        elif p == "/nasty":
            self.send_response(200)
            self.send_header("Refresh", '0;;;url=\x00 ;;url=')
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(NASTY)))
            self.end_headers()
            self.wfile.write(NASTY)
            return
        else:
            self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def dump(*a):
    for k in sorted(COUNT):
        print("%s %d" % (k, COUNT[k]))
    sys.stdout.flush()
    sys.exit(0)


signal.signal(signal.SIGTERM, dump)
S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
