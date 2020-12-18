# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2018 New Vector
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

import argparse
import getpass
import hashlib
import hmac
import logging
import sys

import requests as _requests
import yaml


def request_registration(
    user,
    password,
    server_location,
    shared_secret,
    admin=False,
    user_type=None,
    requests=_requests,
    _print=print,
    exit=sys.exit,
):

    url = "%s/_synapse/admin/v1/register" % (server_location.rstrip("/"),)

    # Get the nonce
    r = requests.get(url, verify=False)

    if r.status_code != 200:
        _print("ERROR! Received %d %s" % (r.status_code, r.reason))
        if 400 <= r.status_code < 500:
            try:
                _print(r.json()["error"])
            except Exception:
                pass
        return exit(1)

    nonce = r.json()["nonce"]

    mac = hmac.new(key=shared_secret.encode("utf8"), digestmod=hashlib.sha1)

    mac.update(nonce.encode("utf8"))
    mac.update(b"\x00")
    mac.update(user.encode("utf8"))
    mac.update(b"\x00")
    mac.update(password.encode("utf8"))
    mac.update(b"\x00")
    mac.update(b"admin" if admin else b"notadmin")
    if user_type:
        mac.update(b"\x00")
        mac.update(user_type.encode("utf8"))

    mac = mac.hexdigest()

    data = {
        "nonce": nonce,
        "username": user,
        "password": password,
        "mac": mac,
        "admin": admin,
        "user_type": user_type,
    }

    _print("Sending registration request...")
    r = requests.post(url, json=data, verify=False)

    if r.status_code != 200:
        _print("ERROR! Received %d %s" % (r.status_code, r.reason))
        if 400 <= r.status_code < 500:
            try:
                _print(r.json()["error"])
            except Exception:
                pass
        return exit(1)

    _print("Success!")


def register_new_user(user, password, server_location, shared_secret, admin, user_type):
    if not user:
        try:
            default_user = getpass.getuser()
        except Exception:
            default_user = None

        if default_user:
            user = input("New user localpart [%s]: " % (default_user,))
            if not user:
                user = default_user
        else:
            user = input("New user localpart: ")

    if not user:
        print("Invalid user name")
        sys.exit(1)

    if not password:
        password = getpass.getpass("Password: ")

        if not password:
            print("Password cannot be blank.")
            sys.exit(1)

        confirm_password = getpass.getpass("Confirm password: ")

        if password != confirm_password:
            print("Passwords do not match")
            sys.exit(1)

    if admin is None:
        admin = input("Make admin [no]: ")
        if admin in ("y", "yes", "true"):
            admin = True
        else:
            admin = False

    request_registration(
        user, password, server_location, shared_secret, bool(admin), user_type
    )


def main():

    logging.captureWarnings(True)

    parser = argparse.ArgumentParser(
        description="Used to register new users with a given homeserver when"
        " registration has been disabled. The homeserver must be"
        " configured with the 'registration_shared_secret' option"
        " set."
    )
    parser.add_argument(
        "-u",
        "--user",
        default=None,
        help="Local part of the new user. Will prompt if omitted.",
    )
    parser.add_argument(
        "-p",
        "--password",
        default=None,
        help="New password for user. Will prompt if omitted.",
    )
    parser.add_argument(
        "-t",
        "--user_type",
        default=None,
        help="User type as specified in synapse.api.constants.UserTypes",
    )
    admin_group = parser.add_mutually_exclusive_group()
    admin_group.add_argument(
        "-a",
        "--admin",
        action="store_true",
        help=(
            "Register new user as an admin. "
            "Will prompt if --no-admin is not set either."
        ),
    )
    admin_group.add_argument(
        "--no-admin",
        action="store_true",
        help=(
            "Register new user as a regular user. "
            "Will prompt if --admin is not set either."
        ),
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-c",
        "--config",
        type=argparse.FileType("r"),
        help="Path to server config file. Used to read in shared secret.",
    )

    group.add_argument(
        "-k", "--shared-secret", help="Shared secret as defined in server config file."
    )

    parser.add_argument(
        "server_url",
        default="https://localhost:8448",
        nargs="?",
        help="URL to use to talk to the homeserver. Defaults to "
        " 'https://localhost:8448'.",
    )

    args = parser.parse_args()

    if "config" in args and args.config:
        config = yaml.safe_load(args.config)
        secret = config.get("registration_shared_secret", None)
        if not secret:
            print("No 'registration_shared_secret' defined in config.")
            sys.exit(1)
    else:
        secret = args.shared_secret

    admin = None
    if args.admin or args.no_admin:
        admin = args.admin

    register_new_user(
        args.user, args.password, args.server_url, secret, admin, args.user_type
    )


if __name__ == "__main__":
    main()
