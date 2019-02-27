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
"""Defines the various valid commands

The VALID_SERVER_COMMANDS and VALID_CLIENT_COMMANDS define which commands are
allowed to be sent by which side.
"""

import logging
import platform

if platform.python_implementation() == "PyPy":
    import json
    _json_encoder = json.JSONEncoder()
else:
    import simplejson as json
    _json_encoder = json.JSONEncoder(namedtuple_as_object=False)

logger = logging.getLogger(__name__)


class Command(object):
    """The base command class.

    All subclasses must set the NAME variable which equates to the name of the
    command on the wire.

    A full command line on the wire is constructed from `NAME + " " + to_line()`

    The default implementation creates a command of form `<NAME> <data>`
    """
    NAME = None

    def __init__(self, data):
        self.data = data

    @classmethod
    def from_line(cls, line):
        """Deserialises a line from the wire into this command. `line` does not
        include the command.
        """
        return cls(line)

    def to_line(self):
        """Serialises the comamnd for the wire. Does not include the command
        prefix.
        """
        return self.data

    def get_logcontext_id(self):
        """Get a suitable string for the logcontext when processing this command"""

        # by default, we just use the command name.
        return self.NAME


class ServerCommand(Command):
    """Sent by the server on new connection and includes the server_name.

    Format::

        SERVER <server_name>
    """
    NAME = "SERVER"


class RdataCommand(Command):
    """Sent by server when a subscribed stream has an update.

    Format::

        RDATA <stream_name> <token> <row_json>

    The `<token>` may either be a numeric stream id OR "batch". The latter case
    is used to support sending multiple updates with the same stream ID. This
    is done by sending an RDATA for each row, with all but the last RDATA having
    a token of "batch" and the last having the final stream ID.

    The client should batch all incoming RDATA with a token of "batch" (per
    stream_name) until it sees an RDATA with a numeric stream ID.

    `<token>` of "batch" maps to the instance variable `token` being None.

    An example of a batched series of RDATA::

        RDATA presence batch ["@foo:example.com", "online", ...]
        RDATA presence batch ["@bar:example.com", "online", ...]
        RDATA presence 59 ["@baz:example.com", "online", ...]
    """
    NAME = "RDATA"

    def __init__(self, stream_name, token, row):
        self.stream_name = stream_name
        self.token = token
        self.row = row

    @classmethod
    def from_line(cls, line):
        stream_name, token, row_json = line.split(" ", 2)
        return cls(
            stream_name,
            None if token == "batch" else int(token),
            json.loads(row_json)
        )

    def to_line(self):
        return " ".join((
            self.stream_name,
            str(self.token) if self.token is not None else "batch",
            _json_encoder.encode(self.row),
        ))

    def get_logcontext_id(self):
        return "RDATA-" + self.stream_name


class PositionCommand(Command):
    """Sent by the server to tell the client the stream postition without
    needing to send an RDATA.

    Sent to the client after all missing updates for a stream have been sent
    to the client and they're now up to date.
    """
    NAME = "POSITION"

    def __init__(self, stream_name, token):
        self.stream_name = stream_name
        self.token = token

    @classmethod
    def from_line(cls, line):
        stream_name, token = line.split(" ", 1)
        return cls(stream_name, int(token))

    def to_line(self):
        return " ".join((self.stream_name, str(self.token),))


class ErrorCommand(Command):
    """Sent by either side if there was an ERROR. The data is a string describing
    the error.
    """
    NAME = "ERROR"


class PingCommand(Command):
    """Sent by either side as a keep alive. The data is arbitary (often timestamp)
    """
    NAME = "PING"


class NameCommand(Command):
    """Sent by client to inform the server of the client's identity. The data
    is the name
    """
    NAME = "NAME"


class ReplicateCommand(Command):
    """Sent by the client to subscribe to the stream.

    Format::

        REPLICATE <stream_name> <token>

    Where <token> may be either:
        * a numeric stream_id to stream updates from
        * "NOW" to stream all subsequent updates.

    The <stream_name> can be "ALL" to subscribe to all known streams, in which
    case the <token> must be set to "NOW", i.e.::

        REPLICATE ALL NOW
    """
    NAME = "REPLICATE"

    def __init__(self, stream_name, token):
        self.stream_name = stream_name
        self.token = token

    @classmethod
    def from_line(cls, line):
        stream_name, token = line.split(" ", 1)
        if token in ("NOW", "now"):
            token = "NOW"
        else:
            token = int(token)
        return cls(stream_name, token)

    def to_line(self):
        return " ".join((self.stream_name, str(self.token),))

    def get_logcontext_id(self):
        return "REPLICATE-" + self.stream_name


class UserSyncCommand(Command):
    """Sent by the client to inform the server that a user has started or
    stopped syncing. Used to calculate presence on the master.

    Includes a timestamp of when the last user sync was.

    Format::

        USER_SYNC <user_id> <state> <last_sync_ms>

    Where <state> is either "start" or "stop"
    """
    NAME = "USER_SYNC"

    def __init__(self, user_id, is_syncing, last_sync_ms):
        self.user_id = user_id
        self.is_syncing = is_syncing
        self.last_sync_ms = last_sync_ms

    @classmethod
    def from_line(cls, line):
        user_id, state, last_sync_ms = line.split(" ", 2)

        if state not in ("start", "end"):
            raise Exception("Invalid USER_SYNC state %r" % (state,))

        return cls(user_id, state == "start", int(last_sync_ms))

    def to_line(self):
        return " ".join((
            self.user_id, "start" if self.is_syncing else "end", str(self.last_sync_ms),
        ))


class FederationAckCommand(Command):
    """Sent by the client when it has processed up to a given point in the
    federation stream. This allows the master to drop in-memory caches of the
    federation stream.

    This must only be sent from one worker (i.e. the one sending federation)

    Format::

        FEDERATION_ACK <token>
    """
    NAME = "FEDERATION_ACK"

    def __init__(self, token):
        self.token = token

    @classmethod
    def from_line(cls, line):
        return cls(int(line))

    def to_line(self):
        return str(self.token)


class SyncCommand(Command):
    """Used for testing. The client protocol implementation allows waiting
    on a SYNC command with a specified data.
    """
    NAME = "SYNC"


class RemovePusherCommand(Command):
    """Sent by the client to request the master remove the given pusher.

    Format::

        REMOVE_PUSHER <app_id> <push_key> <user_id>
    """
    NAME = "REMOVE_PUSHER"

    def __init__(self, app_id, push_key, user_id):
        self.user_id = user_id
        self.app_id = app_id
        self.push_key = push_key

    @classmethod
    def from_line(cls, line):
        app_id, push_key, user_id = line.split(" ", 2)

        return cls(app_id, push_key, user_id)

    def to_line(self):
        return " ".join((self.app_id, self.push_key, self.user_id))


class InvalidateCacheCommand(Command):
    """Sent by the client to invalidate an upstream cache.

    THIS IS NOT RELIABLE, AND SHOULD *NOT* BE USED ACCEPT FOR THINGS THAT ARE
    NOT DISASTROUS IF WE DROP ON THE FLOOR.

    Mainly used to invalidate destination retry timing caches.

    Format::

        INVALIDATE_CACHE <cache_func> <keys_json>

    Where <keys_json> is a json list.
    """
    NAME = "INVALIDATE_CACHE"

    def __init__(self, cache_func, keys):
        self.cache_func = cache_func
        self.keys = keys

    @classmethod
    def from_line(cls, line):
        cache_func, keys_json = line.split(" ", 1)

        return cls(cache_func, json.loads(keys_json))

    def to_line(self):
        return " ".join((
            self.cache_func, _json_encoder.encode(self.keys),
        ))


class UserIpCommand(Command):
    """Sent periodically when a worker sees activity from a client.

    Format::

        USER_IP <user_id>, <access_token>, <ip>, <device_id>, <last_seen>, <user_agent>
    """
    NAME = "USER_IP"

    def __init__(self, user_id, access_token, ip, user_agent, device_id, last_seen):
        self.user_id = user_id
        self.access_token = access_token
        self.ip = ip
        self.user_agent = user_agent
        self.device_id = device_id
        self.last_seen = last_seen

    @classmethod
    def from_line(cls, line):
        user_id, jsn = line.split(" ", 1)

        access_token, ip, user_agent, device_id, last_seen = json.loads(jsn)

        return cls(
            user_id, access_token, ip, user_agent, device_id, last_seen
        )

    def to_line(self):
        return self.user_id + " " + _json_encoder.encode((
            self.access_token, self.ip, self.user_agent, self.device_id,
            self.last_seen,
        ))


# Map of command name to command type.
COMMAND_MAP = {
    cmd.NAME: cmd
    for cmd in (
        ServerCommand,
        RdataCommand,
        PositionCommand,
        ErrorCommand,
        PingCommand,
        NameCommand,
        ReplicateCommand,
        UserSyncCommand,
        FederationAckCommand,
        SyncCommand,
        RemovePusherCommand,
        InvalidateCacheCommand,
        UserIpCommand,
    )
}

# The commands the server is allowed to send
VALID_SERVER_COMMANDS = (
    ServerCommand.NAME,
    RdataCommand.NAME,
    PositionCommand.NAME,
    ErrorCommand.NAME,
    PingCommand.NAME,
    SyncCommand.NAME,
)

# The commands the client is allowed to send
VALID_CLIENT_COMMANDS = (
    NameCommand.NAME,
    ReplicateCommand.NAME,
    PingCommand.NAME,
    UserSyncCommand.NAME,
    FederationAckCommand.NAME,
    RemovePusherCommand.NAME,
    InvalidateCacheCommand.NAME,
    UserIpCommand.NAME,
    ErrorCommand.NAME,
)
