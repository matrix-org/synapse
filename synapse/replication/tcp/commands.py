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
import abc
import logging
import platform
from typing import Tuple, Type

if platform.python_implementation() == "PyPy":
    import json

    _json_encoder = json.JSONEncoder()
else:
    import simplejson as json  # type: ignore[no-redef]  # noqa: F821

    _json_encoder = json.JSONEncoder(namedtuple_as_object=False)  # type: ignore[call-arg]  # noqa: F821

logger = logging.getLogger(__name__)


class Command(metaclass=abc.ABCMeta):
    """The base command class.

    All subclasses must set the NAME variable which equates to the name of the
    command on the wire.

    A full command line on the wire is constructed from `NAME + " " + to_line()`
    """

    NAME = None  # type: str

    @classmethod
    @abc.abstractmethod
    def from_line(cls, line):
        """Deserialises a line from the wire into this command. `line` does not
        include the command.
        """

    @abc.abstractmethod
    def to_line(self) -> str:
        """Serialises the comamnd for the wire. Does not include the command
        prefix.
        """

    def get_logcontext_id(self):
        """Get a suitable string for the logcontext when processing this command"""

        # by default, we just use the command name.
        return self.NAME


class _SimpleCommand(Command):
    """An implementation of Command whose argument is just a 'data' string."""

    def __init__(self, data):
        self.data = data

    @classmethod
    def from_line(cls, line):
        return cls(line)

    def to_line(self) -> str:
        return self.data


class ServerCommand(_SimpleCommand):
    """Sent by the server on new connection and includes the server_name.

    Format::

        SERVER <server_name>
    """

    NAME = "SERVER"


class RdataCommand(Command):
    """Sent by server when a subscribed stream has an update.

    Format::

        RDATA <stream_name> <instance_name> <token> <row_json>

    The `<token>` may either be a numeric stream id OR "batch". The latter case
    is used to support sending multiple updates with the same stream ID. This
    is done by sending an RDATA for each row, with all but the last RDATA having
    a token of "batch" and the last having the final stream ID.

    The client should batch all incoming RDATA with a token of "batch" (per
    stream_name) until it sees an RDATA with a numeric stream ID.

    The `<instance_name>` is the source of the new data (usually "master").

    `<token>` of "batch" maps to the instance variable `token` being None.

    An example of a batched series of RDATA::

        RDATA presence master batch ["@foo:example.com", "online", ...]
        RDATA presence master batch ["@bar:example.com", "online", ...]
        RDATA presence master 59 ["@baz:example.com", "online", ...]
    """

    NAME = "RDATA"

    def __init__(self, stream_name, instance_name, token, row):
        self.stream_name = stream_name
        self.instance_name = instance_name
        self.token = token
        self.row = row

    @classmethod
    def from_line(cls, line):
        stream_name, instance_name, token, row_json = line.split(" ", 3)
        return cls(
            stream_name,
            instance_name,
            None if token == "batch" else int(token),
            json.loads(row_json),
        )

    def to_line(self):
        return " ".join(
            (
                self.stream_name,
                self.instance_name,
                str(self.token) if self.token is not None else "batch",
                _json_encoder.encode(self.row),
            )
        )

    def get_logcontext_id(self):
        return "RDATA-" + self.stream_name


class PositionCommand(Command):
    """Sent by the server to tell the client the stream postition without
    needing to send an RDATA.

    Format::

        POSITION <stream_name> <instance_name> <token>

    On receipt of a POSITION command clients should check if they have missed
    any updates, and if so then fetch them out of band.

    The `<instance_name>` is the process that sent the command and is the source
    of the stream.
    """

    NAME = "POSITION"

    def __init__(self, stream_name, instance_name, token):
        self.stream_name = stream_name
        self.instance_name = instance_name
        self.token = token

    @classmethod
    def from_line(cls, line):
        stream_name, instance_name, token = line.split(" ", 2)
        return cls(stream_name, instance_name, int(token))

    def to_line(self):
        return " ".join((self.stream_name, self.instance_name, str(self.token)))


class ErrorCommand(_SimpleCommand):
    """Sent by either side if there was an ERROR. The data is a string describing
    the error.
    """

    NAME = "ERROR"


class PingCommand(_SimpleCommand):
    """Sent by either side as a keep alive. The data is arbitary (often timestamp)
    """

    NAME = "PING"


class NameCommand(_SimpleCommand):
    """Sent by client to inform the server of the client's identity. The data
    is the name
    """

    NAME = "NAME"


class ReplicateCommand(Command):
    """Sent by the client to subscribe to streams.

    Format::

        REPLICATE
    """

    NAME = "REPLICATE"

    def __init__(self):
        pass

    @classmethod
    def from_line(cls, line):
        return cls()

    def to_line(self):
        return ""


class UserSyncCommand(Command):
    """Sent by the client to inform the server that a user has started or
    stopped syncing on this process.

    This is used by the process handling presence (typically the master) to
    calculate who is online and who is not.

    Includes a timestamp of when the last user sync was.

    Format::

        USER_SYNC <instance_id> <user_id> <state> <last_sync_ms>

    Where <state> is either "start" or "end"
    """

    NAME = "USER_SYNC"

    def __init__(self, instance_id, user_id, is_syncing, last_sync_ms):
        self.instance_id = instance_id
        self.user_id = user_id
        self.is_syncing = is_syncing
        self.last_sync_ms = last_sync_ms

    @classmethod
    def from_line(cls, line):
        instance_id, user_id, state, last_sync_ms = line.split(" ", 3)

        if state not in ("start", "end"):
            raise Exception("Invalid USER_SYNC state %r" % (state,))

        return cls(instance_id, user_id, state == "start", int(last_sync_ms))

    def to_line(self):
        return " ".join(
            (
                self.instance_id,
                self.user_id,
                "start" if self.is_syncing else "end",
                str(self.last_sync_ms),
            )
        )


class ClearUserSyncsCommand(Command):
    """Sent by the client to inform the server that it should drop all
    information about syncing users sent by the client.

    Mainly used when client is about to shut down.

    Format::

        CLEAR_USER_SYNC <instance_id>
    """

    NAME = "CLEAR_USER_SYNC"

    def __init__(self, instance_id):
        self.instance_id = instance_id

    @classmethod
    def from_line(cls, line):
        return cls(line)

    def to_line(self):
        return self.instance_id


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

        return cls(user_id, access_token, ip, user_agent, device_id, last_seen)

    def to_line(self):
        return (
            self.user_id
            + " "
            + _json_encoder.encode(
                (
                    self.access_token,
                    self.ip,
                    self.user_agent,
                    self.device_id,
                    self.last_seen,
                )
            )
        )


class RemoteServerUpCommand(_SimpleCommand):
    """Sent when a worker has detected that a remote server is no longer
    "down" and retry timings should be reset.

    If sent from a client the server will relay to all other workers.

    Format::

        REMOTE_SERVER_UP <server>
    """

    NAME = "REMOTE_SERVER_UP"


_COMMANDS = (
    ServerCommand,
    RdataCommand,
    PositionCommand,
    ErrorCommand,
    PingCommand,
    NameCommand,
    ReplicateCommand,
    UserSyncCommand,
    FederationAckCommand,
    RemovePusherCommand,
    UserIpCommand,
    RemoteServerUpCommand,
    ClearUserSyncsCommand,
)  # type: Tuple[Type[Command], ...]

# Map of command name to command type.
COMMAND_MAP = {cmd.NAME: cmd for cmd in _COMMANDS}

# The commands the server is allowed to send
VALID_SERVER_COMMANDS = (
    ServerCommand.NAME,
    RdataCommand.NAME,
    PositionCommand.NAME,
    ErrorCommand.NAME,
    PingCommand.NAME,
    RemoteServerUpCommand.NAME,
)

# The commands the client is allowed to send
VALID_CLIENT_COMMANDS = (
    NameCommand.NAME,
    ReplicateCommand.NAME,
    PingCommand.NAME,
    UserSyncCommand.NAME,
    ClearUserSyncsCommand.NAME,
    FederationAckCommand.NAME,
    RemovePusherCommand.NAME,
    UserIpCommand.NAME,
    ErrorCommand.NAME,
    RemoteServerUpCommand.NAME,
)


def parse_command_from_line(line: str) -> Command:
    """Parses a command from a received line.

    Line should already be stripped of whitespace and be checked if blank.
    """

    idx = line.find(" ")
    if idx >= 0:
        cmd_name = line[:idx]
        rest_of_line = line[idx + 1 :]
    else:
        cmd_name = line
        rest_of_line = ""

    cmd_cls = COMMAND_MAP[cmd_name]
    return cmd_cls.from_line(rest_of_line)
