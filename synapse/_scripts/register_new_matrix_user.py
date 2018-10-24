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

from __future__ import print_function

import getpass
import hashlib
import hmac
import sys

from six import input

import requests as _requests


def request_registration(
    user, password, server_location, shared_secret, admin=False, requests=_requests
):

    url = "%s/_matrix/client/r0/admin/register" % (server_location,)

    # Get the nonce
    r = requests.get(url)

    if not r.ok:
        print("ERROR! Received %d %s" % (r.status_code, r.reason))
        if 400 <= r.status_code < 500:
            try:
                print(r.json()["error"])
            except Exception:
                pass
        sys.exit(1)

    nonce = r.json()["nonce"]

    mac = hmac.new(key=shared_secret, digestmod=hashlib.sha1)

    mac.update(nonce.encode('utf8'))
    mac.update(b"\x00")
    mac.update(user.encode('utf8'))
    mac.update(b"\x00")
    mac.update(password.encode('utf8'))
    mac.update(b"\x00")
    mac.update(b"admin" if admin else b"notadmin")

    mac = mac.hexdigest()

    data = {
        "nonce": nonce,
        "username": user,
        "password": password,
        "mac": mac,
        "admin": admin,
    }

    print("Sending registration request...")
    r = requests.post(url, json=data)

    if not r.ok:
        print("ERROR! Received %d %s" % (r.status_code, r.reason))
        if 400 <= r.status_code < 500:
            try:
                print(r.json()["error"])
            except Exception:
                pass
        sys.exit(1)

    print("Success!")


def register_new_user(user, password, server_location, shared_secret, admin):
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

    request_registration(user, password, server_location, shared_secret, bool(admin))
