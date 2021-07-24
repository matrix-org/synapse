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


""" This is an example of using the server to server implementation to do a
basic chat style thing. It accepts commands from stdin and outputs to stdout.

It assumes that ucids are of the form <user>@<domain>, and uses <domain> as
the address of the remote home server to hit.

Usage:
    python test_messaging.py <port>

Currently assumes the local address is localhost:<port>

"""


import argparse
import curses.wrapper
import json
import logging
import os
import re

import cursesio

from twisted.internet import defer, reactor
from twisted.python import log

from synapse.app.homeserver import SynapseHomeServer
from synapse.federation import ReplicationHandler
from synapse.federation.units import Pdu
from synapse.util import origin_from_ucid

# from synapse.logging.utils import log_function


logger = logging.getLogger("example")


def excpetion_errback(failure):
    logging.exception(failure)


class InputOutput:
    """This is responsible for basic I/O so that a user can interact with
    the example app.
    """

    def __init__(self, screen, user):
        self.screen = screen
        self.user = user

    def set_home_server(self, server):
        self.server = server

    def on_line(self, line):
        """This is where we process commands."""

        try:
            m = re.match(r"^join (\S+)$", line)
            if m:
                # The `sender` wants to join a room.
                (room_name,) = m.groups()
                self.print_line("%s joining %s" % (self.user, room_name))
                self.server.join_room(room_name, self.user, self.user)
                # self.print_line("OK.")
                return

            m = re.match(r"^invite (\S+) (\S+)$", line)
            if m:
                # `sender` wants to invite someone to a room
                room_name, invitee = m.groups()
                self.print_line("%s invited to %s" % (invitee, room_name))
                self.server.invite_to_room(room_name, self.user, invitee)
                # self.print_line("OK.")
                return

            m = re.match(r"^send (\S+) (.*)$", line)
            if m:
                # `sender` wants to message a room
                room_name, body = m.groups()
                self.print_line("%s send to %s" % (self.user, room_name))
                self.server.send_message(room_name, self.user, body)
                # self.print_line("OK.")
                return

            m = re.match(r"^backfill (\S+)$", line)
            if m:
                # we want to backfill a room
                (room_name,) = m.groups()
                self.print_line("backfill %s" % room_name)
                self.server.backfill(room_name)
                return

            self.print_line("Unrecognized command")

        except Exception as e:
            logger.exception(e)

    def print_line(self, text):
        self.screen.print_line(text)

    def print_log(self, text):
        self.screen.print_log(text)


class IOLoggerHandler(logging.Handler):
    def __init__(self, io):
        logging.Handler.__init__(self)
        self.io = io

    def emit(self, record):
        if record.levelno < logging.WARN:
            return

        msg = self.format(record)
        self.io.print_log(msg)


class Room:
    """Used to store (in memory) the current membership state of a room, and
    which home servers we should send PDUs associated with the room to.
    """

    def __init__(self, room_name):
        self.room_name = room_name
        self.invited = set()
        self.participants = set()
        self.servers = set()

        self.oldest_server = None

        self.have_got_metadata = False

    def add_participant(self, participant):
        """Someone has joined the room"""
        self.participants.add(participant)
        self.invited.discard(participant)

        server = origin_from_ucid(participant)
        self.servers.add(server)

        if not self.oldest_server:
            self.oldest_server = server

    def add_invited(self, invitee):
        """Someone has been invited to the room"""
        self.invited.add(invitee)
        self.servers.add(origin_from_ucid(invitee))


class HomeServer(ReplicationHandler):
    """A very basic home server implentation that allows people to join a
    room and then invite other people.
    """

    def __init__(self, server_name, replication_layer, output):
        self.server_name = server_name
        self.replication_layer = replication_layer
        self.replication_layer.set_handler(self)

        self.joined_rooms = {}

        self.output = output

    def on_receive_pdu(self, pdu):
        """We just received a PDU"""
        pdu_type = pdu.pdu_type

        if pdu_type == "sy.room.message":
            self._on_message(pdu)
        elif pdu_type == "sy.room.member" and "membership" in pdu.content:
            if pdu.content["membership"] == "join":
                self._on_join(pdu.context, pdu.state_key)
            elif pdu.content["membership"] == "invite":
                self._on_invite(pdu.origin, pdu.context, pdu.state_key)
        else:
            self.output.print_line(
                "#%s (unrec) %s = %s"
                % (pdu.context, pdu.pdu_type, json.dumps(pdu.content))
            )

    def _on_message(self, pdu):
        """We received a message"""
        self.output.print_line(
            "#%s %s %s" % (pdu.context, pdu.content["sender"], pdu.content["body"])
        )

    def _on_join(self, context, joinee):
        """Someone has joined a room, either a remote user or a local user"""
        room = self._get_or_create_room(context)
        room.add_participant(joinee)

        self.output.print_line("#%s %s %s" % (context, joinee, "*** JOINED"))

    def _on_invite(self, origin, context, invitee):
        """Someone has been invited"""
        room = self._get_or_create_room(context)
        room.add_invited(invitee)

        self.output.print_line("#%s %s %s" % (context, invitee, "*** INVITED"))

        if not room.have_got_metadata and origin is not self.server_name:
            logger.debug("Get room state")
            self.replication_layer.get_state_for_context(origin, context)
            room.have_got_metadata = True

    @defer.inlineCallbacks
    def send_message(self, room_name, sender, body):
        """Send a message to a room!"""
        destinations = yield self.get_servers_for_context(room_name)

        try:
            yield self.replication_layer.send_pdu(
                Pdu.create_new(
                    context=room_name,
                    pdu_type="sy.room.message",
                    content={"sender": sender, "body": body},
                    origin=self.server_name,
                    destinations=destinations,
                )
            )
        except Exception as e:
            logger.exception(e)

    @defer.inlineCallbacks
    def join_room(self, room_name, sender, joinee):
        """Join a room!"""
        self._on_join(room_name, joinee)

        destinations = yield self.get_servers_for_context(room_name)

        try:
            pdu = Pdu.create_new(
                context=room_name,
                pdu_type="sy.room.member",
                is_state=True,
                state_key=joinee,
                content={"membership": "join"},
                origin=self.server_name,
                destinations=destinations,
            )
            yield self.replication_layer.send_pdu(pdu)
        except Exception as e:
            logger.exception(e)

    @defer.inlineCallbacks
    def invite_to_room(self, room_name, sender, invitee):
        """Invite someone to a room!"""
        self._on_invite(self.server_name, room_name, invitee)

        destinations = yield self.get_servers_for_context(room_name)

        try:
            yield self.replication_layer.send_pdu(
                Pdu.create_new(
                    context=room_name,
                    is_state=True,
                    pdu_type="sy.room.member",
                    state_key=invitee,
                    content={"membership": "invite"},
                    origin=self.server_name,
                    destinations=destinations,
                )
            )
        except Exception as e:
            logger.exception(e)

    def backfill(self, room_name, limit=5):
        room = self.joined_rooms.get(room_name)

        if not room:
            return

        dest = room.oldest_server

        return self.replication_layer.backfill(dest, room_name, limit)

    def _get_room_remote_servers(self, room_name):
        return list(self.joined_rooms.setdefault(room_name).servers)

    def _get_or_create_room(self, room_name):
        return self.joined_rooms.setdefault(room_name, Room(room_name))

    def get_servers_for_context(self, context):
        return defer.succeed(
            self.joined_rooms.setdefault(context, Room(context)).servers
        )


def main(stdscr):
    parser = argparse.ArgumentParser()
    parser.add_argument("user", type=str)
    parser.add_argument("-v", "--verbose", action="count")
    args = parser.parse_args()

    user = args.user
    server_name = origin_from_ucid(user)

    # Set up logging

    root_logger = logging.getLogger()

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(message)s"
    )
    if not os.path.exists("logs"):
        os.makedirs("logs")
    fh = logging.FileHandler("logs/%s" % user)
    fh.setFormatter(formatter)

    root_logger.addHandler(fh)
    root_logger.setLevel(logging.DEBUG)

    # Hack: The only way to get it to stop logging to sys.stderr :(
    log.theLogPublisher.observers = []
    observer = log.PythonLoggingObserver()
    observer.start()

    # Set up synapse server

    curses_stdio = cursesio.CursesStdIO(stdscr)
    input_output = InputOutput(curses_stdio, user)

    curses_stdio.set_callback(input_output)

    app_hs = SynapseHomeServer(server_name, db_name="dbs/%s" % user)
    replication = app_hs.get_replication_layer()

    hs = HomeServer(server_name, replication, curses_stdio)

    input_output.set_home_server(hs)

    # Add input_output logger
    io_logger = IOLoggerHandler(input_output)
    io_logger.setFormatter(formatter)
    root_logger.addHandler(io_logger)

    # Start!

    try:
        port = int(server_name.split(":")[1])
    except Exception:
        port = 12345

    app_hs.get_http_server().start_listening(port)

    reactor.addReader(curses_stdio)

    reactor.run()


if __name__ == "__main__":
    curses.wrapper(main)
