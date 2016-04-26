# Copyright 2016 OpenMarket Ltd
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

from twisted.conch.manhole import ColoredManhole
from twisted.conch.insults import insults
from twisted.conch import manhole_ssh
from twisted.cred import checkers, portal
from twisted.conch.ssh.keys import Key

PUBLIC_KEY = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAGEArzJx8OYOnJmzf4tfBEvLi8DVPrJ3/c9k2I/Az"
    "64fxjHf9imyRJbixtQhlH9lfNjUIx+4LmrJH5QNRsFporcHDKOTwTTYLh5KmRpslkYHRivcJS"
    "kbh/C+BR3utDS555mV"
)

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIByAIBAAJhAK8ycfDmDpyZs3+LXwRLy4vA1T6yd/3PZNiPwM+uH8Yx3/YpskSW
4sbUIZR/ZXzY1CMfuC5qyR+UDUbBaaK3Bwyjk8E02C4eSpkabJZGB0Yr3CUpG4fw
vgUd7rQ0ueeZlQIBIwJgbh+1VZfr7WftK5lu7MHtqE1S1vPWZQYE3+VUn8yJADyb
Z4fsZaCrzW9lkIqXkE3GIY+ojdhZhkO1gbG0118sIgphwSWKRxK0mvh6ERxKqIt1
xJEJO74EykXZV4oNJ8sjAjEA3J9r2ZghVhGN6V8DnQrTk24Td0E8hU8AcP0FVP+8
PQm/g/aXf2QQkQT+omdHVEJrAjEAy0pL0EBH6EVS98evDCBtQw22OZT52qXlAwZ2
gyTriKFVoqjeEjt3SZKKqXHSApP/AjBLpF99zcJJZRq2abgYlf9lv1chkrWqDHUu
DZttmYJeEfiFBBavVYIF1dOlZT0G8jMCMBc7sOSZodFnAiryP+Qg9otSBjJ3bQML
pSTqy7c3a2AScC/YyOwkDaICHnnD3XyjMwIxALRzl0tQEKMXs6hH8ToUdlLROCrP
EhQ0wahUTCk1gKA4uPD6TMTChavbh4K63OvbKg==
-----END RSA PRIVATE KEY-----"""


def manhole(username, password, globals):
    """Starts a ssh listener with password authentication using
    the given username and password. Clients connecting to the ssh
    listener will find themselves in a colored python shell with
    the supplied globals.

    Args:
        username(str): The username ssh clients should auth with.
        password(str): The password ssh clients should auth with.
        globals(dict): The variables to expose in the shell.

    Returns:
        twisted.internet.protocol.Factory: A factory to pass to ``listenTCP``
    """

    checker = checkers.InMemoryUsernamePasswordDatabaseDontUse(
        **{username: password}
    )

    rlm = manhole_ssh.TerminalRealm()
    rlm.chainedProtocolFactory = lambda: insults.ServerProtocol(
        ColoredManhole,
        dict(globals, __name__="__console__")
    )

    factory = manhole_ssh.ConchFactory(portal.Portal(rlm, [checker]))
    factory.publicKeys['ssh-rsa'] = Key.fromString(PUBLIC_KEY)
    factory.privateKeys['ssh-rsa'] = Key.fromString(PRIVATE_KEY)

    return factory
