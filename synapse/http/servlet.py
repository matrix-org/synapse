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

from synapse.api.errors import SynapseError, Codes

import logging
import simplejson

logger = logging.getLogger(__name__)


def parse_integer(request, name, default=None, required=False):
    """Parse an integer parameter from the request string

    :param request: the twisted HTTP request.
    :param name (str): the name of the query parameter.
    :param default: value to use if the parameter is absent, defaults to None.
    :param required (bool): whether to raise a 400 SynapseError if the
        parameter is absent, defaults to False.
    :return: An int value or the default.
    :raises
        SynapseError if the parameter is absent and required, or if the
            parameter is present and not an integer.
    """
    if name in request.args:
        try:
            return int(request.args[name][0])
        except:
            message = "Query parameter %r must be an integer" % (name,)
            raise SynapseError(400, message)
    else:
        if required:
            message = "Missing integer query parameter %r" % (name,)
            raise SynapseError(400, message, errcode=Codes.MISSING_PARAM)
        else:
            return default


def parse_boolean(request, name, default=None, required=False):
    """Parse a boolean parameter from the request query string

    :param request: the twisted HTTP request.
    :param name (str): the name of the query parameter.
    :param default: value to use if the parameter is absent, defaults to None.
    :param required (bool): whether to raise a 400 SynapseError if the
        parameter is absent, defaults to False.
    :return: A bool value or the default.
    :raises
        SynapseError if the parameter is absent and required, or if the
            parameter is present and not one of "true" or "false".
    """

    if name in request.args:
        try:
            return {
                "true": True,
                "false": False,
            }[request.args[name][0]]
        except:
            message = (
                "Boolean query parameter %r must be one of"
                " ['true', 'false']"
            ) % (name,)
            raise SynapseError(400, message)
    else:
        if required:
            message = "Missing boolean query parameter %r" % (name,)
            raise SynapseError(400, message, errcode=Codes.MISSING_PARAM)
        else:
            return default


def parse_string(request, name, default=None, required=False,
                 allowed_values=None, param_type="string"):
    """Parse a string parameter from the request query string.

    :param request: the twisted HTTP request.
    :param name (str): the name of the query parameter.
    :param default: value to use if the parameter is absent, defaults to None.
    :param required (bool): whether to raise a 400 SynapseError if the
        parameter is absent, defaults to False.
    :param allowed_values (list): List of allowed values for the string,
        or None if any value is allowed, defaults to None
    :return: A string value or the default.
    :raises
        SynapseError if the parameter is absent and required, or if the
            parameter is present, must be one of a list of allowed values and
            is not one of those allowed values.
    """

    if name in request.args:
        value = request.args[name][0]
        if allowed_values is not None and value not in allowed_values:
            message = "Query parameter %r must be one of [%s]" % (
                name, ", ".join(repr(v) for v in allowed_values)
            )
            raise SynapseError(400, message)
        else:
            return value
    else:
        if required:
            message = "Missing %s query parameter %r" % (param_type, name)
            raise SynapseError(400, message, errcode=Codes.MISSING_PARAM)
        else:
            return default


def parse_json_value_from_request(request):
    """Parse a JSON value from the body of a twisted HTTP request.

    :param request: the twisted HTTP request.
    :returns: The JSON value.
    :raises
        SynapseError if the request body couldn't be decoded as JSON.
    """
    try:
        content_bytes = request.content.read()
    except:
        raise SynapseError(400, "Error reading JSON content.")

    try:
        content = simplejson.loads(content_bytes)
    except simplejson.JSONDecodeError:
        raise SynapseError(400, "Content not JSON.", errcode=Codes.NOT_JSON)

    return content


def parse_json_object_from_request(request):
    """Parse a JSON object from the body of a twisted HTTP request.

    :param request: the twisted HTTP request.
    :raises
        SynapseError if the request body couldn't be decoded as JSON or
            if it wasn't a JSON object.
    """
    content = parse_json_value_from_request(request)

    if type(content) != dict:
        message = "Content must be a JSON object."
        raise SynapseError(400, message, errcode=Codes.BAD_JSON)

    return content


class RestServlet(object):

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
      on_OPTIONS

    Automatically handles turning CodeMessageExceptions thrown by these methods
    into the appropriate HTTP response.
    """

    def register(self, http_server):
        """ Register this servlet with the given HTTP server. """
        if hasattr(self, "PATTERNS"):
            patterns = self.PATTERNS

            for method in ("GET", "PUT", "POST", "OPTIONS", "DELETE"):
                if hasattr(self, "on_%s" % (method,)):
                    method_handler = getattr(self, "on_%s" % (method,))
                    http_server.register_paths(method, patterns, method_handler)

        else:
            raise NotImplementedError("RestServlet must register something.")
