import argparse
import BaseHTTPServer
import os
import SimpleHTTPServer

from daemonize import Daemonize


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
        SimpleHTTPServer.SimpleHTTPRequestHandler
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
