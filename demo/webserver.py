import argparse
import BaseHTTPServer
import os
import SimpleHTTPServer
import cgi, logging

from daemonize import Daemonize

class SimpleHTTPRequestHandlerWithPOST(SimpleHTTPServer.SimpleHTTPRequestHandler):
    UPLOAD_PATH = "upload"

    """
    Accept all post request as file upload
    """
    def do_POST(self):

        path = os.path.join(self.UPLOAD_PATH, os.path.basename(self.path))
        length = self.headers['content-length']
        data = self.rfile.read(int(length))

        with open(path, 'wb') as fh:
            fh.write(data)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        # Return the absolute path of the uploaded file
        self.wfile.write('{"url":"/%s"}' % path)


def setup():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("-p", "--port", dest="port", type=int, default=8080)
    parser.add_argument('-P', "--pid-file", dest="pid", default="web.pid")
    args = parser.parse_args()

    # Get absolute path to directory to serve, as daemonize changes to '/'
    os.chdir(args.directory)
    dr = os.getcwd()

    httpd = BaseHTTPServer.HTTPServer(
        ('', args.port),
        SimpleHTTPRequestHandlerWithPOST
    )

    def run():
        os.chdir(dr)
        httpd.serve_forever()

    daemon = Daemonize(
            app="synapse-webclient",
            pid=args.pid,
            action=run,
            auto_close_fds=False,
        )

    daemon.start()

if __name__ == '__main__':
    setup()
