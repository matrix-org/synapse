from functools import wraps

from canonicaljson import json
from jsonschema import validate

from contextlib import closing
import socket


def validate_schema(schema):
    def _wrap_validate(func):
        @wraps(func)
        def _do_validate(request):
            body = json.loads(request.content.read())
            validate(instance=body, schema=schema)
            return func(request, body)

        return _do_validate

    return _wrap_validate


def port_checker(port):
    if port < 0 or 65535 < port:
        return False

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        try:
            sock.bind((socket.gethostname(), port))
            sock.listen()
            sock.close()
            return True
        except:
            return False
