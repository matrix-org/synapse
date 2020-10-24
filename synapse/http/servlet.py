# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" This module contains base REST classes for constructing REST servlets. """

import logging
import re
from typing import Any, Dict, Iterable, Pattern, Tuple, Union

from synapse.api.errors import Codes, SynapseError
from synapse.util import json_decoder

logger = logging.getLogger(__name__)


def parse_integer(request, name, default=None, required=False):
    """Parse an integer parameter from the request string

    Args:
        request: the twisted HTTP request.
        name (bytes/unicode): the name of the query parameter.
        default (int|None): value to use if the parameter is absent, defaults
            to None.
        required (bool): whether to raise a 400 SynapseError if the
            parameter is absent, defaults to False.

    Returns:
        int|None: An int value or the default.

    Raises:
        SynapseError: if the parameter is absent and required, or if the
            parameter is present and not an integer.
    """
    return parse_integer_from_args(request.args, name, default, required)


def parse_integer_from_args(args, name, default=None, required=False):

    if not isinstance(name, bytes):
        name = name.encode("ascii")

    if name in args:
        try:
            return int(args[name][0])
        except Exception:
            message = "Query parameter %r must be an integer" % (name,)
            raise SynapseError(400, message, errcode=Codes.INVALID_PARAM)
    else:
        if required:
            message = "Missing integer query parameter %r" % (name,)
            raise SynapseError(400, message, errcode=Codes.MISSING_PARAM)
        else:
            return default


def parse_boolean(request, name, default=None, required=False):
    """Parse a boolean parameter from the request query string

    Args:
        request: the twisted HTTP request.
        name (bytes/unicode): the name of the query parameter.
        default (bool|None): value to use if the parameter is absent, defaults
            to None.
        required (bool): whether to raise a 400 SynapseError if the
            parameter is absent, defaults to False.

    Returns:
        bool|None: A bool value or the default.

    Raises:
        SynapseError: if the parameter is absent and required, or if the
            parameter is present and not one of "true" or "false".
    """

    return parse_boolean_from_args(request.args, name, default, required)


def parse_boolean_from_args(args, name, default=None, required=False):

    if not isinstance(name, bytes):
        name = name.encode("ascii")

    if name in args:
        try:
            return {b"true": True, b"false": False}[args[name][0]]
        except Exception:
            message = (
                "Boolean query parameter %r must be one of ['true', 'false']"
            ) % (name,)
            raise SynapseError(400, message)
    else:
        if required:
            message = "Missing boolean query parameter %r" % (name,)
            raise SynapseError(400, message, errcode=Codes.MISSING_PARAM)
        else:
            return default


def parse_string(
    request,
    name,
    default=None,
    required=False,
    allowed_values=None,
    param_type="string",
    encoding="ascii",
):
    """
    Parse a string parameter from the request query string.

    If encoding is not None, the content of the query param will be
    decoded to Unicode using the encoding, otherwise it will be encoded

    Args:
        request: the twisted HTTP request.
        name (bytes|unicode): the name of the query parameter.
        default (bytes|unicode|None): value to use if the parameter is absent,
            defaults to None. Must be bytes if encoding is None.
        required (bool): whether to raise a 400 SynapseError if the
            parameter is absent, defaults to False.
        allowed_values (list[bytes|unicode]): List of allowed values for the
            string, or None if any value is allowed, defaults to None. Must be
            the same type as name, if given.
        encoding (str|None): The encoding to decode the string content with.

    Returns:
        bytes/unicode|None: A string value or the default. Unicode if encoding
        was given, bytes otherwise.

    Raises:
        SynapseError if the parameter is absent and required, or if the
            parameter is present, must be one of a list of allowed values and
            is not one of those allowed values.
    """
    return parse_string_from_args(
        request.args, name, default, required, allowed_values, param_type, encoding
    )


def parse_string_from_args(
    args,
    name,
    default=None,
    required=False,
    allowed_values=None,
    param_type="string",
    encoding="ascii",
):

    if not isinstance(name, bytes):
        name = name.encode("ascii")

    if name in args:
        value = args[name][0]

        if encoding:
            try:
                value = value.decode(encoding)
            except ValueError:
                raise SynapseError(
                    400, "Query parameter %r must be %s" % (name, encoding)
                )

        if allowed_values is not None and value not in allowed_values:
            message = "Query parameter %r must be one of [%s]" % (
                name,
                ", ".join(repr(v) for v in allowed_values),
            )
            raise SynapseError(400, message)
        else:
            return value
    else:
        if required:
            message = "Missing %s query parameter %r" % (param_type, name)
            raise SynapseError(400, message, errcode=Codes.MISSING_PARAM)
        else:

            if encoding and isinstance(default, bytes):
                return default.decode(encoding)

            return default


def parse_json_value_from_request(request, allow_empty_body=False):
    """Parse a JSON value from the body of a twisted HTTP request.

    Args:
        request: the twisted HTTP request.
        allow_empty_body (bool): if True, an empty body will be accepted and
            turned into None

    Returns:
        The JSON value.

    Raises:
        SynapseError if the request body couldn't be decoded as JSON.
    """
    try:
        content_bytes = request.content.read()
    except Exception:
        raise SynapseError(400, "Error reading JSON content.")

    if not content_bytes and allow_empty_body:
        return None

    try:
        content = json_decoder.decode(content_bytes.decode("utf-8"))
    except Exception as e:
        logger.warning("Unable to parse JSON: %s", e)
        raise SynapseError(400, "Content not JSON.", errcode=Codes.NOT_JSON)

    return content


def parse_json_object_from_request(request, allow_empty_body=False):
    """Parse a JSON object from the body of a twisted HTTP request.

    Args:
        request: the twisted HTTP request.
        allow_empty_body (bool): if True, an empty body will be accepted and
            turned into an empty dict.

    Raises:
        SynapseError if the request body couldn't be decoded as JSON or
            if it wasn't a JSON object.
    """
    content = parse_json_value_from_request(request, allow_empty_body=allow_empty_body)

    if allow_empty_body and content is None:
        return {}

    if type(content) != dict:
        message = "Content must be a JSON object."
        raise SynapseError(400, message, errcode=Codes.BAD_JSON)

    return content


def assert_params_in_dict(body, required):
    absent = []
    for k in required:
        if k not in body:
            absent.append(k)

    if len(absent) > 0:
        raise SynapseError(400, "Missing params: %r" % absent, Codes.MISSING_PARAM)


class RestServlet:

    """ A Synapse REST Servlet.

    An implementing class can either provide its own custom 'register' method,
    or use the automatic pattern handling provided by the base class.

    To use this latter, the implementing class instead provides a `PATTERN`
    class attribute containing a pre-compiled regular expression. The automatic
    register method will then use this method to register any of the following
    instance methods associated with the corresponding HTTP method:

      on_GET
      on_PUT
      on_POST
      on_DELETE

    Automatically handles turning CodeMessageExceptions thrown by these methods
    into the appropriate HTTP response.
    """

    def register(self, http_server):
        """ Register this servlet with the given HTTP server. """

        has_decorated = False

        for item in (getattr(self, attr) for attr in dir(self)):
            if callable(item) and hasattr(item, "_on") and isinstance(item._on, tuple):
                has_decorated = True
                self._register_decorated_method(http_server, item)

        if hasattr(self, "PATTERNS"):
            patterns = self.PATTERNS

            for method in ("GET", "PUT", "POST", "DELETE"):
                if hasattr(self, "on_%s" % (method,)):
                    servlet_classname = self.__class__.__name__
                    method_handler = getattr(self, "on_%s" % (method,))

                    if hasattr(method_handler, "_on"):
                        # already handled by _register_decorated_method
                        continue

                    http_server.register_paths(
                        method, patterns, method_handler, servlet_classname
                    )

        elif not has_decorated:
            raise NotImplementedError("RestServlet must register something.")

    @classmethod
    def _register_decorated_method(cls, http_server, method):
        on = method._on  # type: Tuple[str, PATH_ARG, dict]

        if isinstance(on[1], str):
            cls._register_decorated(http_server, on[0], on[1], on[2], method)
        elif isinstance(on[1], Iterable):
            for path_aggregate in on[1]:
                if isinstance(path_aggregate, str):
                    cls._register_decorated(
                        http_server, on[0], path_aggregate, on[2], method,
                    )
                elif isinstance(path_aggregate, tuple):
                    cls._register_decorated(
                        http_server,
                        on[0],
                        path_aggregate[0],
                        {**on[2], **path_aggregate[1]},
                        method,
                    )

    @classmethod
    def _register_decorated(
        cls,
        http_server,
        http_method: str,
        pattern: str,
        pattern_kwargs: Dict[str, Any],
        method,
    ):
        http_server.register_paths(
            http_method,
            cls._decorated_pattern(transform_path(pattern), **pattern_kwargs),
            method,
            cls.__name__,
        )

    @classmethod
    def _decorated_pattern(cls, pattern: str, **kwargs: Any) -> Iterable[Pattern]:
        raise NotImplementedError(
            "Tried to define a decorated handler without a pattern function in servlet class."
        )


RE_SUGAR = re.compile(r"{(\w+)}")


def transform_path(orig_path) -> str:
    return RE_SUGAR.sub(r"(?P<\1>[^/]*)", orig_path)


PATH_ARG = Union[str, Iterable[Union[str, Tuple[str, dict]]]]


class _On:
    def __init__(self, on_method: str, path_arg: PATH_ARG, **pattern_kwargs):
        def _internal(method):
            method._on = (on_method, path_arg, pattern_kwargs)
            return method

        self.function = _internal

    def __call__(self, method):
        return self.function(method)


class on(_On):
    @classmethod
    def get(cls, path_arg: PATH_ARG, **pattern_kwargs):
        return cls("GET", path_arg, **pattern_kwargs)

    @classmethod
    def post(cls, path_arg: PATH_ARG, **pattern_kwargs):
        return cls("POST", path_arg, **pattern_kwargs)

    @classmethod
    def put(cls, path_arg: PATH_ARG, **pattern_kwargs):
        return cls("PUT", path_arg, **pattern_kwargs)

    @classmethod
    def options(cls, path_arg: PATH_ARG, **pattern_kwargs):
        return cls("OPTIONS", path_arg, **pattern_kwargs)

    @classmethod
    def delete(cls, path_arg: PATH_ARG, **pattern_kwargs):
        return cls("DELETE", path_arg, **pattern_kwargs)
