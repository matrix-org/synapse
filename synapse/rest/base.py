# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
import re


def client_path_pattern(path_regex):
    """Creates a regex compiled client path with the correct client path
    prefix.

    Args:
        path_regex (str): The regex string to match. This should NOT have a ^
        as this will be prefixed.
    Returns:
        SRE_Pattern
    """
    return re.compile("^/matrix/client/api/v1" + path_regex)


class RestServletFactory(object):

    """ A factory for creating REST servlets.

    These REST servlets represent the entire client-server REST API. Generally
    speaking, they serve as wrappers around events and the handlers that
    process them.

    See synapse.api.events for information on synapse events.
    """

    def __init__(self, hs):
        http_server = hs.get_http_server()

        # You get import errors if you try to import before the classes in this
        # file are defined, hence importing here instead.

        import room
        room.register_servlets(hs, http_server)

        import events
        events.register_servlets(hs, http_server)

        import register
        register.register_servlets(hs, http_server)

        import profile
        profile.register_servlets(hs, http_server)

        import public
        public.register_servlets(hs, http_server)

        import presence
        presence.register_servlets(hs, http_server)

        import im
        im.register_servlets(hs, http_server)

        import login
        login.register_servlets(hs, http_server)


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

    def __init__(self, hs):
        self.hs = hs

        self.handlers = hs.get_handlers()
        self.event_factory = hs.get_event_factory()
        self.auth = hs.get_auth()

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
