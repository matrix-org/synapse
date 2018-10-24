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

def request_registration(user, password, server_location, shared_secret, admin=False):
    req = urllib2.Request(
        "%s/_matrix/client/r0/admin/register" % (server_location,),
        headers={'Content-Type': 'application/json'},
    )

    try:
        if sys.version_info[:3] >= (2, 7, 9):
            # As of version 2.7.9, urllib2 now checks SSL certs
            import ssl

            f = urllib2.urlopen(req, context=ssl.SSLContext(ssl.PROTOCOL_SSLv23))
        else:
            f = urllib2.urlopen(req)
        body = f.read()
        f.close()
        nonce = json.loads(body)["nonce"]
    except urllib2.HTTPError as e:
        print("ERROR! Received %d %s" % (e.code, e.reason))
        if 400 <= e.code < 500:
            if e.info().type == "application/json":
                resp = json.load(e)
                if "error" in resp:
                    print(resp["error"])
        sys.exit(1)

    mac = hmac.new(key=shared_secret, digestmod=hashlib.sha1)

    mac.update(nonce)
    mac.update("\x00")
    mac.update(user)
    mac.update("\x00")
    mac.update(password)
    mac.update("\x00")
    mac.update("admin" if admin else "notadmin")

    mac = mac.hexdigest()

    data = {
        "nonce": nonce,
        "username": user,
        "password": password,
        "mac": mac,
        "admin": admin,
    }

    server_location = server_location.rstrip("/")

    print("Sending registration request...")

    req = urllib2.Request(
        "%s/_matrix/client/r0/admin/register" % (server_location,),
        data=json.dumps(data),
        headers={'Content-Type': 'application/json'},
    )
    try:
        if sys.version_info[:3] >= (2, 7, 9):
            # As of version 2.7.9, urllib2 now checks SSL certs
            import ssl

            f = urllib2.urlopen(req, context=ssl.SSLContext(ssl.PROTOCOL_SSLv23))
        else:
            f = urllib2.urlopen(req)
        f.read()
        f.close()
        print("Success.")
    except urllib2.HTTPError as e:
        print("ERROR! Received %d %s" % (e.code, e.reason))
        if 400 <= e.code < 500:
            if e.info().type == "application/json":
                resp = json.load(e)
                if "error" in resp:
                    print(resp["error"])
        sys.exit(1)


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
