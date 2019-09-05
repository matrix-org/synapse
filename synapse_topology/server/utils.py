from functools import wraps

from canonicaljson import json
from jsonschema import validate

from contextlib import closing
import socket


def validate_schema(schema):
    def _wrap_validate(func):
        @wraps(func)
        def _do_validate(self, request):
            body = json.loads(request.content.read())
            print(body)
            validate(instance=body, schema=schema)
            return func(self, request, body)

        return _do_validate

    return _wrap_validate


def port_checker(port):
    if port < 0 or 65535 < port:
        return False

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        try:
            sock.bind(("0.0.0.0", port))
            sock.listen()
            return True
        except:
            return False


def log_body_if_fail(func):
    @wraps(func)
    def _log_wrapper(self, request):
        try:
            return func(self, request)
        except Exception:
            body = json.loads(request.content.read())
            print(body)
            raise

    return _log_wrapper
