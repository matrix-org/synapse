#!/usr/bin/env python

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

""" Starts a synapse client console. """
import argparse
import cmd
import getpass
import json
import shlex
import sys
import time
import urllib
from http import TwistedHttpClient
from typing import Optional

import nacl.encoding
import nacl.signing
import urlparse
from signedjson.sign import SignatureVerifyException, verify_signed_json

from twisted.internet import defer, reactor, threads

CONFIG_JSON = "cmdclient_config.json"

# TODO: The concept of trusted identity servers has been deprecated. This option and checks
#  should be removed
TRUSTED_ID_SERVERS = ["localhost:8001"]


class SynapseCmd(cmd.Cmd):

    """Basic synapse command-line processor.

    This processes commands from the user and calls the relevant HTTP methods.
    """

    def __init__(self, http_client, server_url, identity_server_url, username, token):
        cmd.Cmd.__init__(self)
        self.http_client = http_client
        self.http_client.verbose = True
        self.config = {
            "url": server_url,
            "identityServerUrl": identity_server_url,
            "user": username,
            "token": token,
            "verbose": "on",
            "complete_usernames": "on",
            "send_delivery_receipts": "on",
        }
        self.path_prefix = "/_matrix/client/api/v1"
        self.event_stream_token = "END"
        self.prompt = ">>> "

    def do_EOF(self, line):  # allows CTRL+D quitting
        return True

    def emptyline(self):
        pass  # else it repeats the previous command

    def _usr(self):
        return self.config["user"]

    def _tok(self):
        return self.config["token"]

    def _url(self):
        return self.config["url"] + self.path_prefix

    def _identityServerUrl(self):
        return self.config["identityServerUrl"]

    def _is_on(self, config_name):
        if config_name in self.config:
            return self.config[config_name] == "on"
        return False

    def _domain(self):
        if "user" not in self.config or not self.config["user"]:
            return None
        return self.config["user"].split(":")[1]

    def do_config(self, line):
        """Show the config for this client: "config"
        Edit a key value mapping: "config key value" e.g. "config token 1234"
        Config variables:
            user: The username to auth with.
            token: The access token to auth with.
            url: The url of the server.
            verbose: [on|off] The verbosity of requests/responses.
            complete_usernames: [on|off] Auto complete partial usernames by
            assuming they are on the same homeserver as you.
            E.g. name >> @name:yourhost
            send_delivery_receipts: [on|off] Automatically send receipts to
            messages when performing a 'stream' command.
        Additional key/values can be added and can be substituted into requests
        by using $. E.g. 'config roomid room1' then 'raw get /rooms/$roomid'.
        """
        if len(line) == 0:
            print(json.dumps(self.config, indent=4))
            return

        try:
            args = self._parse(line, ["key", "val"], force_keys=True)

            # make sure restricted config values are checked
            config_rules = [  # key, valid_values
                ("verbose", ["on", "off"]),
                ("complete_usernames", ["on", "off"]),
                ("send_delivery_receipts", ["on", "off"]),
            ]
            for key, valid_vals in config_rules:
                if key == args["key"] and args["val"] not in valid_vals:
                    print("%s value must be one of %s" % (args["key"], valid_vals))
                    return

            # toggle the http client verbosity
            if args["key"] == "verbose":
                self.http_client.verbose = "on" == args["val"]

            # assign the new config
            self.config[args["key"]] = args["val"]
            print(json.dumps(self.config, indent=4))

            save_config(self.config)
        except Exception as e:
            print(e)

    def do_register(self, line):
        """Registers for a new account: "register <userid> <noupdate>"
        <userid> : The desired user ID
        <noupdate> : Do not automatically clobber config values.
        """
        args = self._parse(line, ["userid", "noupdate"])

        password = None
        pwd = None
        pwd2 = "_"
        while pwd != pwd2:
            pwd = getpass.getpass("Type a password for this user: ")
            pwd2 = getpass.getpass("Retype the password: ")
            if pwd != pwd2 or len(pwd) == 0:
                print("Password mismatch.")
                pwd = None
            else:
                password = pwd

        body = {"type": "m.login.password"}
        if "userid" in args:
            body["user"] = args["userid"]
        if password:
            body["password"] = password

        reactor.callFromThread(self._do_register, body, "noupdate" not in args)

    @defer.inlineCallbacks
    def _do_register(self, data, update_config):
        # check the registration flows
        url = self._url() + "/register"
        json_res = yield self.http_client.do_request("GET", url)
        print(json.dumps(json_res, indent=4))

        passwordFlow = None
        for flow in json_res["flows"]:
            if flow["type"] == "m.login.recaptcha" or (
                "stages" in flow and "m.login.recaptcha" in flow["stages"]
            ):
                print("Unable to register: Home server requires captcha.")
                return
            if flow["type"] == "m.login.password" and "stages" not in flow:
                passwordFlow = flow
                break

        if not passwordFlow:
            return

        json_res = yield self.http_client.do_request("POST", url, data=data)
        print(json.dumps(json_res, indent=4))
        if update_config and "user_id" in json_res:
            self.config["user"] = json_res["user_id"]
            self.config["token"] = json_res["access_token"]
            save_config(self.config)

    def do_login(self, line):
        """Login as a specific user: "login @bob:localhost"
        You MAY be prompted for a password, or instructed to visit a URL.
        """
        try:
            args = self._parse(line, ["user_id"], force_keys=True)
            can_login = threads.blockingCallFromThread(reactor, self._check_can_login)
            if can_login:
                p = getpass.getpass("Enter your password: ")
                user = args["user_id"]
                if self._is_on("complete_usernames") and not user.startswith("@"):
                    domain = self._domain()
                    if domain:
                        user = "@" + user + ":" + domain

                reactor.callFromThread(self._do_login, user, p)
                # print " got %s " % p
        except Exception as e:
            print(e)

    @defer.inlineCallbacks
    def _do_login(self, user, password):
        path = "/login"
        data = {"user": user, "password": password, "type": "m.login.password"}
        url = self._url() + path
        json_res = yield self.http_client.do_request("POST", url, data=data)
        print(json_res)

        if "access_token" in json_res:
            self.config["user"] = user
            self.config["token"] = json_res["access_token"]
            save_config(self.config)
            print("Login successful.")

    @defer.inlineCallbacks
    def _check_can_login(self):
        path = "/login"
        # ALWAYS check that the home server can handle the login request before
        # submitting!
        url = self._url() + path
        json_res = yield self.http_client.do_request("GET", url)
        print(json_res)

        if "flows" not in json_res:
            print("Failed to find any login flows.")
            defer.returnValue(False)

        flow = json_res["flows"][0]  # assume first is the one we want.
        if "type" not in flow or "m.login.password" != flow["type"] or "stages" in flow:
            fallback_url = self._url() + "/login/fallback"
            print(
                "Unable to login via the command line client. Please visit "
                "%s to login." % fallback_url
            )
            defer.returnValue(False)
        defer.returnValue(True)

    def do_emailrequest(self, line):
        """Requests the association of a third party identifier
        <address> The email address)
        <clientSecret> A string of characters generated when requesting an email that you'll supply in subsequent calls to identify yourself
        <sendAttempt> The number of times the user has requested an email. Leave this the same between requests to retry the request at the transport level. Increment it to request that the email be sent again.
        """
        args = self._parse(line, ["address", "clientSecret", "sendAttempt"])

        postArgs = {
            "email": args["address"],
            "clientSecret": args["clientSecret"],
            "sendAttempt": args["sendAttempt"],
        }

        reactor.callFromThread(self._do_emailrequest, postArgs)

    @defer.inlineCallbacks
    def _do_emailrequest(self, args):
        # TODO: Update to use v2 Identity Service API endpoint
        url = (
            self._identityServerUrl()
            + "/_matrix/identity/api/v1/validate/email/requestToken"
        )

        json_res = yield self.http_client.do_request(
            "POST",
            url,
            data=urllib.urlencode(args),
            jsonreq=False,
            headers={"Content-Type": ["application/x-www-form-urlencoded"]},
        )
        print(json_res)
        if "sid" in json_res:
            print("Token sent. Your session ID is %s" % (json_res["sid"]))

    def do_emailvalidate(self, line):
        """Validate and associate a third party ID
        <sid> The session ID (sid) given to you in the response to requestToken
        <token> The token sent to your third party identifier address
        <clientSecret> The same clientSecret you supplied in requestToken
        """
        args = self._parse(line, ["sid", "token", "clientSecret"])

        postArgs = {
            "sid": args["sid"],
            "token": args["token"],
            "clientSecret": args["clientSecret"],
        }

        reactor.callFromThread(self._do_emailvalidate, postArgs)

    @defer.inlineCallbacks
    def _do_emailvalidate(self, args):
        # TODO: Update to use v2 Identity Service API endpoint
        url = (
            self._identityServerUrl()
            + "/_matrix/identity/api/v1/validate/email/submitToken"
        )

        json_res = yield self.http_client.do_request(
            "POST",
            url,
            data=urllib.urlencode(args),
            jsonreq=False,
            headers={"Content-Type": ["application/x-www-form-urlencoded"]},
        )
        print(json_res)

    def do_3pidbind(self, line):
        """Validate and associate a third party ID
        <sid> The session ID (sid) given to you in the response to requestToken
        <clientSecret> The same clientSecret you supplied in requestToken
        """
        args = self._parse(line, ["sid", "clientSecret"])

        postArgs = {"sid": args["sid"], "clientSecret": args["clientSecret"]}
        postArgs["mxid"] = self.config["user"]

        reactor.callFromThread(self._do_3pidbind, postArgs)

    @defer.inlineCallbacks
    def _do_3pidbind(self, args):
        # TODO: Update to use v2 Identity Service API endpoint
        url = self._identityServerUrl() + "/_matrix/identity/api/v1/3pid/bind"

        json_res = yield self.http_client.do_request(
            "POST",
            url,
            data=urllib.urlencode(args),
            jsonreq=False,
            headers={"Content-Type": ["application/x-www-form-urlencoded"]},
        )
        print(json_res)

    def do_join(self, line):
        """Joins a room: "join <roomid>" """
        try:
            args = self._parse(line, ["roomid"], force_keys=True)
            self._do_membership_change(args["roomid"], "join", self._usr())
        except Exception as e:
            print(e)

    def do_joinalias(self, line):
        try:
            args = self._parse(line, ["roomname"], force_keys=True)
            path = "/join/%s" % urllib.quote(args["roomname"])
            reactor.callFromThread(self._run_and_pprint, "POST", path, {})
        except Exception as e:
            print(e)

    def do_topic(self, line):
        """ "topic [set|get] <roomid> [<newtopic>]"
        Set the topic for a room: topic set <roomid> <newtopic>
        Get the topic for a room: topic get <roomid>
        """
        try:
            args = self._parse(line, ["action", "roomid", "topic"])
            if "action" not in args or "roomid" not in args:
                print("Must specify set|get and a room ID.")
                return
            if args["action"].lower() not in ["set", "get"]:
                print("Must specify set|get, not %s" % args["action"])
                return

            path = "/rooms/%s/topic" % urllib.quote(args["roomid"])

            if args["action"].lower() == "set":
                if "topic" not in args:
                    print("Must specify a new topic.")
                    return
                body = {"topic": args["topic"]}
                reactor.callFromThread(self._run_and_pprint, "PUT", path, body)
            elif args["action"].lower() == "get":
                reactor.callFromThread(self._run_and_pprint, "GET", path)
        except Exception as e:
            print(e)

    def do_invite(self, line):
        """Invite a user to a room: "invite <userid> <roomid>" """
        try:
            args = self._parse(line, ["userid", "roomid"], force_keys=True)

            user_id = args["userid"]

            reactor.callFromThread(self._do_invite, args["roomid"], user_id)
        except Exception as e:
            print(e)

    @defer.inlineCallbacks
    def _do_invite(self, roomid, userstring):
        if not userstring.startswith("@") and self._is_on("complete_usernames"):
            # TODO: Update to use v2 Identity Service API endpoint
            url = self._identityServerUrl() + "/_matrix/identity/api/v1/lookup"

            json_res = yield self.http_client.do_request(
                "GET", url, qparams={"medium": "email", "address": userstring}
            )

            mxid = None

            if "mxid" in json_res and "signatures" in json_res:
                # TODO: Update to use v2 Identity Service API endpoint
                url = (
                    self._identityServerUrl()
                    + "/_matrix/identity/api/v1/pubkey/ed25519"
                )

                pubKey = None
                pubKeyObj = yield self.http_client.do_request("GET", url)
                if "public_key" in pubKeyObj:
                    pubKey = nacl.signing.VerifyKey(
                        pubKeyObj["public_key"], encoder=nacl.encoding.HexEncoder
                    )
                else:
                    print("No public key found in pubkey response!")

                sigValid = False

                if pubKey:
                    for signame in json_res["signatures"]:
                        if signame not in TRUSTED_ID_SERVERS:
                            print(
                                "Ignoring signature from untrusted server %s"
                                % (signame)
                            )
                        else:
                            try:
                                verify_signed_json(json_res, signame, pubKey)
                                sigValid = True
                                print(
                                    "Mapping %s -> %s correctly signed by %s"
                                    % (userstring, json_res["mxid"], signame)
                                )
                                break
                            except SignatureVerifyException as e:
                                print("Invalid signature from %s" % (signame))
                                print(e)

                if sigValid:
                    print("Resolved 3pid %s to %s" % (userstring, json_res["mxid"]))
                    mxid = json_res["mxid"]
                else:
                    print(
                        "Got association for %s but couldn't verify signature"
                        % (userstring)
                    )

            if not mxid:
                mxid = "@" + userstring + ":" + self._domain()

            self._do_membership_change(roomid, "invite", mxid)

    def do_leave(self, line):
        """Leaves a room: "leave <roomid>" """
        try:
            args = self._parse(line, ["roomid"], force_keys=True)
            self._do_membership_change(args["roomid"], "leave", self._usr())
        except Exception as e:
            print(e)

    def do_send(self, line):
        """Sends a message. "send <roomid> <body>" """
        args = self._parse(line, ["roomid", "body"])
        txn_id = "txn%s" % int(time.time())
        path = "/rooms/%s/send/m.room.message/%s" % (
            urllib.quote(args["roomid"]),
            txn_id,
        )
        body_json = {"msgtype": "m.text", "body": args["body"]}
        reactor.callFromThread(self._run_and_pprint, "PUT", path, body_json)

    def do_list(self, line):
        """List data about a room.
        "list members <roomid> [query]" - List all the members in this room.
        "list messages <roomid> [query]" - List all the messages in this room.

        Where [query] will be directly applied as query parameters, allowing
        you to use the pagination API. E.g. the last 3 messages in this room:
        "list messages <roomid> from=END&to=START&limit=3"
        """
        args = self._parse(line, ["type", "roomid", "qp"])
        if "type" not in args or "roomid" not in args:
            print("Must specify type and room ID.")
            return
        if args["type"] not in ["members", "messages"]:
            print("Unrecognised type: %s" % args["type"])
            return
        room_id = args["roomid"]
        path = "/rooms/%s/%s" % (urllib.quote(room_id), args["type"])

        qp = {"access_token": self._tok()}
        if "qp" in args:
            for key_value_str in args["qp"].split("&"):
                try:
                    key_value = key_value_str.split("=")
                    qp[key_value[0]] = key_value[1]
                except Exception:
                    print("Bad query param: %s" % key_value)
                    return

        reactor.callFromThread(self._run_and_pprint, "GET", path, query_params=qp)

    def do_create(self, line):
        """Creates a room.
        "create [public|private] <roomname>" - Create a room <roomname> with the
                                             specified visibility.
        "create <roomname>" - Create a room <roomname> with default visibility.
        "create [public|private]" - Create a room with specified visibility.
        "create" - Create a room with default visibility.
        """
        args = self._parse(line, ["vis", "roomname"])
        # fixup args depending on which were set
        body = {}
        if "vis" in args and args["vis"] in ["public", "private"]:
            body["visibility"] = args["vis"]

        if "roomname" in args:
            room_name = args["roomname"]
            body["room_alias_name"] = room_name
        elif "vis" in args and args["vis"] not in ["public", "private"]:
            room_name = args["vis"]
            body["room_alias_name"] = room_name

        reactor.callFromThread(self._run_and_pprint, "POST", "/createRoom", body)

    def do_raw(self, line):
        """Directly send a JSON object: "raw <method> <path> <data> <notoken>"
        <method>: Required. One of "PUT", "GET", "POST", "xPUT", "xGET",
        "xPOST". Methods with 'x' prefixed will not automatically append the
        access token.
        <path>: Required. E.g. "/events"
        <data>: Optional. E.g. "{ "msgtype":"custom.text", "body":"abc123"}"
        """
        args = self._parse(line, ["method", "path", "data"])
        # sanity check
        if "method" not in args or "path" not in args:
            print("Must specify path and method.")
            return

        args["method"] = args["method"].upper()
        valid_methods = [
            "PUT",
            "GET",
            "POST",
            "DELETE",
            "XPUT",
            "XGET",
            "XPOST",
            "XDELETE",
        ]
        if args["method"] not in valid_methods:
            print("Unsupported method: %s" % args["method"])
            return

        if "data" not in args:
            args["data"] = None
        else:
            try:
                args["data"] = json.loads(args["data"])
            except Exception as e:
                print("Data is not valid JSON. %s" % e)
                return

        qp = {"access_token": self._tok()}
        if args["method"].startswith("X"):
            qp = {}  # remove access token
            args["method"] = args["method"][1:]  # snip the X
        else:
            # append any query params the user has set
            try:
                parsed_url = urlparse.urlparse(args["path"])
                qp.update(urlparse.parse_qs(parsed_url.query))
                args["path"] = parsed_url.path
            except Exception:
                pass

        reactor.callFromThread(
            self._run_and_pprint,
            args["method"],
            args["path"],
            args["data"],
            query_params=qp,
        )

    def do_stream(self, line):
        """Stream data from the server: "stream <longpoll timeout ms>" """
        args = self._parse(line, ["timeout"])
        timeout = 5000
        if "timeout" in args:
            try:
                timeout = int(args["timeout"])
            except ValueError:
                print("Timeout must be in milliseconds.")
                return
        reactor.callFromThread(self._do_event_stream, timeout)

    @defer.inlineCallbacks
    def _do_event_stream(self, timeout):
        res = yield defer.ensureDeferred(
            self.http_client.get_json(
                self._url() + "/events",
                {
                    "access_token": self._tok(),
                    "timeout": str(timeout),
                    "from": self.event_stream_token,
                },
            )
        )
        print(json.dumps(res, indent=4))

        if "chunk" in res:
            for event in res["chunk"]:
                if (
                    event["type"] == "m.room.message"
                    and self._is_on("send_delivery_receipts")
                    and event["user_id"] != self._usr()
                ):  # not sent by us
                    self._send_receipt(event, "d")

        # update the position in the stram
        if "end" in res:
            self.event_stream_token = res["end"]

    def _send_receipt(self, event, feedback_type):
        path = "/rooms/%s/messages/%s/%s/feedback/%s/%s" % (
            urllib.quote(event["room_id"]),
            event["user_id"],
            event["msg_id"],
            self._usr(),
            feedback_type,
        )
        data = {}
        reactor.callFromThread(
            self._run_and_pprint,
            "PUT",
            path,
            data=data,
            alt_text="Sent receipt for %s" % event["msg_id"],
        )

    def _do_membership_change(self, roomid, membership, userid):
        path = "/rooms/%s/state/m.room.member/%s" % (
            urllib.quote(roomid),
            urllib.quote(userid),
        )
        data = {"membership": membership}
        reactor.callFromThread(self._run_and_pprint, "PUT", path, data=data)

    def do_displayname(self, line):
        """Get or set my displayname: "displayname [new_name]" """
        args = self._parse(line, ["name"])
        path = "/profile/%s/displayname" % (self.config["user"])

        if "name" in args:
            data = {"displayname": args["name"]}
            reactor.callFromThread(self._run_and_pprint, "PUT", path, data=data)
        else:
            reactor.callFromThread(self._run_and_pprint, "GET", path)

    def _do_presence_state(self, state, line):
        args = self._parse(line, ["msgstring"])
        path = "/presence/%s/status" % (self.config["user"])
        data = {"state": state}
        if "msgstring" in args:
            data["status_msg"] = args["msgstring"]

        reactor.callFromThread(self._run_and_pprint, "PUT", path, data=data)

    def do_offline(self, line):
        """Set my presence state to OFFLINE"""
        self._do_presence_state(0, line)

    def do_away(self, line):
        """Set my presence state to AWAY"""
        self._do_presence_state(1, line)

    def do_online(self, line):
        """Set my presence state to ONLINE"""
        self._do_presence_state(2, line)

    def _parse(self, line, keys, force_keys=False):
        """Parses the given line.

        Args:
            line : The line to parse
            keys : A list of keys to map onto the args
            force_keys : True to enforce that the line has a value for every key
        Returns:
            A dict of key:arg
        """
        line_args = shlex.split(line)
        if force_keys and len(line_args) != len(keys):
            raise IndexError("Must specify all args: %s" % keys)

        # do $ substitutions
        for i, arg in enumerate(line_args):
            for config_key in self.config:
                if ("$" + config_key) in arg:
                    arg = arg.replace("$" + config_key, self.config[config_key])
            line_args[i] = arg

        return dict(zip(keys, line_args))

    @defer.inlineCallbacks
    def _run_and_pprint(
        self,
        method,
        path,
        data=None,
        query_params: Optional[dict] = None,
        alt_text=None,
    ):
        """Runs an HTTP request and pretty prints the output.

        Args:
            method: HTTP method
            path: Relative path
            data: Raw JSON data if any
            query_params: dict of query parameters to add to the url
        """
        query_params = query_params or {"access_token": None}

        url = self._url() + path
        if "access_token" in query_params:
            query_params["access_token"] = self._tok()

        json_res = yield self.http_client.do_request(
            method, url, data=data, qparams=query_params
        )
        if alt_text:
            print(alt_text)
        else:
            print(json.dumps(json_res, indent=4))


def save_config(config):
    with open(CONFIG_JSON, "w") as out:
        json.dump(config, out)


def main(server_url, identity_server_url, username, token, config_path):
    print("Synapse command line client")
    print("===========================")
    print("Server: %s" % server_url)
    print("Type 'help' to get started.")
    print("Close this console with CTRL+C then CTRL+D.")
    if not username or not token:
        print("-  'register <username>' - Register an account")
        print("-  'stream' - Connect to the event stream")
        print("-  'create <roomid>' - Create a room")
        print("-  'send <roomid> <message>' - Send a message")
    http_client = TwistedHttpClient()

    # the command line client
    syn_cmd = SynapseCmd(http_client, server_url, identity_server_url, username, token)

    # load synapse.json config from a previous session
    global CONFIG_JSON
    CONFIG_JSON = config_path  # bit cheeky, but just overwrite the global
    try:
        with open(config_path, "r") as config:
            syn_cmd.config = json.load(config)
            try:
                http_client.verbose = "on" == syn_cmd.config["verbose"]
            except Exception:
                pass
            print("Loaded config from %s" % config_path)
    except Exception:
        pass

    # Twisted-specific: Runs the command processor in Twisted's event loop
    # to maintain a single thread for both commands and event processing.
    # If using another HTTP client, just call syn_cmd.cmdloop()
    reactor.callInThread(syn_cmd.cmdloop)
    reactor.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Starts a synapse client.")
    parser.add_argument(
        "-s",
        "--server",
        dest="server",
        default="http://localhost:8008",
        help="The URL of the home server to talk to.",
    )
    parser.add_argument(
        "-i",
        "--identity-server",
        dest="identityserver",
        default="http://localhost:8090",
        help="The URL of the identity server to talk to.",
    )
    parser.add_argument(
        "-u", "--username", dest="username", help="Your username on the server."
    )
    parser.add_argument("-t", "--token", dest="token", help="Your access token.")
    parser.add_argument(
        "-c",
        "--config",
        dest="config",
        default=CONFIG_JSON,
        help="The location of the config.json file to read from.",
    )
    args = parser.parse_args()

    if not args.server:
        print("You must supply a server URL to communicate with.")
        parser.print_help()
        sys.exit(1)

    server = args.server
    if not server.startswith("http://"):
        server = "http://" + args.server

    main(server, args.identityserver, args.username, args.token, args.config)
