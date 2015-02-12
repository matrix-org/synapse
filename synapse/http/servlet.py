# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from synapse.api.errors import SynapseError

import logging


logger = logging.getLogger(__name__)


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
        if hasattr(self, "PATTERN"):
            pattern = self.PATTERN

            for method in ("GET", "PUT", "POST", "OPTIONS", "DELETE"):
                if hasattr(self, "on_%s" % (method)):
                    method_handler = getattr(self, "on_%s" % (method))
                    http_server.register_path(method, pattern, method_handler)
        else:
            raise NotImplementedError("RestServlet must register something.")

    @staticmethod
    def parse_integer(request, name, default=None, required=False):
        if name in request.args:
            try:
                return int(request.args[name][0])
            except:
                message = "Query parameter %r must be an integer" % (name,)
                raise SynapseError(400, message)
        else:
            if required:
                message = "Missing integer query parameter %r" % (name,)
                raise SynapseError(400, message)
            else:
                return default

    @staticmethod
    def parse_boolean(request, name, default=None, required=False):
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
                raise SynapseError(400, message)
            else:
                return default

    @staticmethod
    def parse_string(request, name, default=None, required=False,
                     allowed_values=None, param_type="string"):
        if name in request.args:
            value = request.args[name][0]
            if allowed_values is not None and value not in allowed_values:
                message = "Query parameter %r must be one of [%s]" % (
                    name, ", ".join(repr(v) for v in allowed_values)
                )
                raise SynapseError(message)
            else:
                return value
        else:
            if required:
                message = "Missing %s query parameter %r" % (param_type, name)
                raise SynapseError(400, message)
            else:
                return default
