from functools import wraps

from canonicaljson import json
from jsonschema import validate


def validate_schema(schema):
    def _wrap_validate(func):
        @wraps(func)
        def _do_validate(request):
            body = json.loads(request.content.read())
            validate(instance=body, schema=schema)
            return func(request, body)

        return _do_validate

    return _wrap_validate
