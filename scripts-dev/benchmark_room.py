# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import random
import uuid

import click
import nio
import treq
import yaml

from twisted.internet import reactor
from twisted.internet.defer import Deferred, DeferredList, ensureDeferred
from twisted.internet.task import react

from synapse._scripts.register_new_matrix_user import request_registration

api = nio.Api()


def sleep(time):
    d = Deferred()
    reactor.callLater(time, d.callback, True)
    return d


@click.command()
@click.option("--config")
@click.option("--endpoint", default="http://localhost:8008")
@click.option("--users", default=1, help="Number of users.")
@click.option("--messages", default=1, help="Number of messages per user.", type=int)
@click.option("--time-between", default=5)
@click.option("--jitter", default=2.5)
@click.option("--room")
@click.option("--sync/--no-sync", default=True, help="Whether to sync")
@click.option("--smeared/--instant", default=True, help="Whether to smear user logins")
def main(config, endpoint, users, messages, time_between, jitter, room, sync, smeared):

    with open(config, "r") as f:
        config = yaml.safe_load(f.read())

    output = []

    made_users = []

    with click.progressbar(
        range(users), length=users, label="Creating users..."
    ) as bar:
        for u in bar:
            user = uuid.uuid4().hex
            password = uuid.uuid4().hex

            u = request_registration(
                user,
                password,
                endpoint,
                config["registration_shared_secret"],
                admin=False,
                user_type=None,
                _print=output.append,
            )

            made_users.append((user, password))

    async def do_request(cmd, resp_type, *extra_args):

        method, path, body = cmd
        resp = await treq.request(method, endpoint + path, data=body.encode("utf8"))
        body = await treq.content(resp)
        assert resp.code == 200, body
        resp_body = await treq.json_content(resp)
        matrix_response = resp_type.from_dict(resp_body, *extra_args)
        return matrix_response

    user_clients = {}

    async def login_user(reactor, username, password, done):

        client = nio.Client(username)

        resp = await do_request(
            api.login(username, password), nio.responses.LoginResponse
        )
        client.receive_response(resp)

        resp = await do_request(
            api.join(client.access_token, room), nio.responses.JoinResponse
        )
        client.receive_response(resp)

        user_clients[username] = client
        done()

    async def send_messages(reactor, username, done):

        client = user_clients[username]

        for i in range(1, messages + 1):

            jitter_amount = random.random() * jitter
            await sleep(jitter_amount)

            message = {
                "body": "slaps with a fish for the %s time" % (i,),
                "format": "org.matrix.custom.html",
                "formatted_body": "<strong>slaps with a fish for the %s time</strong>"
                % (i,),
                "msgtype": "m.text",
            }

            r = await do_request(
                api.room_send(
                    client.access_token,
                    room,
                    "m.room.message",
                    message,
                    uuid.uuid4().hex,
                ),
                nio.responses.RoomSendResponse,
                room,
            )
            done()

            await sleep(time_between)

    async def run(reactor):

        d = []

        prog = click.progressbar(length=len(made_users), label="Logging in...")

        def on_login():
            prog.update(1)

        for u in made_users:
            d.append(ensureDeferred(login_user(reactor, *u, on_login)))

        await DeferredList(d)

        prog = click.progressbar(
            length=len(made_users) * messages,
            label="Sending messages...",
            show_pos=True,
        )
        prog.update(0)

        def on_message():
            prog.update(1)

        for u in made_users:
            d.append(ensureDeferred(send_messages(reactor, u[0], on_message)))

        await DeferredList(d)

        print("done!")

    react(lambda reactor: ensureDeferred(run(reactor)))


if __name__ == "__main__":
    main()
