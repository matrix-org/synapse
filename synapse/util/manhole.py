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

from twisted.conch import manhole_ssh
from twisted.conch.insults import insults
from twisted.conch.manhole import ColoredManhole
from twisted.conch.ssh.keys import Key
from twisted.cred import checkers, portal

PUBLIC_KEY ="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDnWgGzx9pRh9cc+qRHUOamvvVmm05nDW5c38AyOjWLIj+bRyGORKZqPzBIibBbP5xo/LsLObkkYy4F1Ou4sRJRgp544TIAhyfH2EP4PMHQfXRTLVH/TPKBxEs3X0Aovp9dExZRSAaqEKCBWHyf8E9jniLNnOF1sK9AD8cXHpn0Qw=="

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDnWgGzx9pRh9cc+qRHUOamvvVmm05nDW5c38AyOjWLIj+bRyGO
RKZqPzBIibBbP5xo/LsLObkkYy4F1Ou4sRJRgp544TIAhyfH2EP4PMHQfXRTLVH/
TPKBxEs3X0Aovp9dExZRSAaqEKCBWHyf8E9jniLNnOF1sK9AD8cXHpn0QwIDAQAB
AoGANbTxXDjy96ZfS7zr0hp30RHXikBXjRjTHABdb8uPjoMe3P9ATPSm5VdR8CT2
qdg0iTLSgSKfVlEn5/ar2i5RH+Xh4i+YHAJ1uTT/SYg4lfFoJeNLRZdw83HFK5o8
v4n4sJcrsdmBUEXuYrilDmToZJSksJT+Wx7JiuyOmLWRFjECQQD/OqjaojC6L39a
A78Ly3BhbMeu1orlA7m3MRnwQSi2szmdAnd1VZv4px4VwD01Mocg0Z/HsqoSxUJn
/IwxbOcPAkEA6AzinGogdTTuj0Vlp8o4OwXF7Ome1Kg6uqzJRuAk1eBRGOuvd5Ki
4yCmakg7HyaHQxv8gKFQus+ckHGkqx4/jQJBAJxNiTDzmNG82sn+d1Y6zWTsoFEj
VEYyBN76c/8deFiC4+qSoyO5PN6HQbZiV1mnyvc/SRGcCema4jMah6SRI+MCQQDm
f94dtwGUy0ZoxGts118xqdNoOMvPu2fTBE1O/Nk6Jf8IfRyn7t2kNUt46VTo5XGY
xNT1xMeXOSDxDiGe5IYFAkEA+OKJEwgK2p9awPU+i5FF2XBm9JBKzesC6oYJNX1K
9jPQ9cNZf3wApY80cWHHqlmkko/DmTA2z+eotOLn/UW0Ww==
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
