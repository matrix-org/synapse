# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
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

"""This module implements the TCP replication protocol used by synapse to
communicate between the master process and its workers (when they're enabled).

The protocol is based on fire and forget, line based commands. An example flow
would be (where '>' indicates master->worker and '<' worker->master flows)::

    > SERVER example.com
    < REPLICATE events 53
    > RDATA events 54 ["$foo1:bar.com", ...]
    > RDATA events 55 ["$foo4:bar.com", ...]

The example shows the server accepting a new connection and sending its identity
with the `SERVER` command, followed by the client asking to subscribe to the
`events` stream from the token `53`. The server then periodically sends `RDATA`
commands which have the format `RDATA <stream_name> <token> <row>`, where the
format of `<row>` is defined by the individual streams.

Error reporting happens by either the client or server sending an `ERROR`
command, and usually the connection will be closed.


Structure of the module:
 * client.py   - the client classes used for workers to connect to master
 * command.py  - the definitions of all the valid commands
 * protocol.py - contains bot the client and server protocol implementations,
                 these should not be used directly
 * resource.py - the server classes that accepts and handle client connections
 * streams.py  - the definitons of all the valid streams

Further details can be found in docs/tcp_replication.rst
"""
