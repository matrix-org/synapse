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

Further detail about the wire protocol can be found in protocol.py and the
meaning of the various commands in command.py.


Since the protocol is a simple line based, its possible to manually connect to
the server using a tool like netcat. A few things should be noted when manually
using the protocol:
 * When subscribing to a stream using `REPLICATE`, the special token `NOW` can
   be used to get all future updates. The special stream name `ALL` can be used
   with `NOW` to subscribe to all available streams.
 * The federation stream is only available if federation sending has been
   disabled on the main process.
 * The server will only time connections out that have sent a `PING` command.
   If a ping is sent then the connection will be closed if no further commands
   are receieved within 15s. Both the client and server protocol implementations
   will send an initial PING on connection and ensure at least one command every
   5s is sent (not necessarily `PING`).
 * `RDATA` commands *usually* include a numeric token, however if the stream
   has multiple rows to replicate per token the server will send multiple
   `RDATA` commands, with all but the last having a token of `batch`. See
   the documentation on `commands.RdataCommand` for further details.
"""
