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

from . import (
    room, events, register, profile, public, presence, im, directory
)

class RestServletFactory(object):

    """ A factory for creating REST servlets.

    These REST servlets represent the entire client-server REST API. Generally
    speaking, they serve as wrappers around events and the handlers that
    process them.

    See synapse.api.events for information on synapse events.
    """

    def __init__(self, hs):
        http_server = hs.get_http_server()

        # TODO(erikj): There *must* be a better way of doing this.
        room.register_servlets(hs, http_server)
        events.register_servlets(hs, http_server)
        register.register_servlets(hs, http_server)
        profile.register_servlets(hs, http_server)
        public.register_servlets(hs, http_server)
        presence.register_servlets(hs, http_server)
        im.register_servlets(hs, http_server)
        directory.register_servlets(hs, http_server)


