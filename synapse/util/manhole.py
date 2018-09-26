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

PUBLIC_KEY = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHhGATaW4KhE23+7nrH4jFx3yLq9OjaEs5"
    "XALqeK+7385NlLja3DE/DO9mGhnd9+bAy39EKT3sTV6+WXQ4yD0TvEEyUEMtjWkSEm6U32+C"
    "DaS3TW/vPBUMeJQwq+Ydcif1UlnpXrDDTamD0AU9VaEvHq+3HAkipqn0TGpKON6aqk4vauDx"
    "oXSsV5TXBVrxP/y7HpMOpU4GUWsaaacBTKKNnUaQB4UflvydaPJUuwdaCUJGTMjbhWrjVfK+"
    "jslseSPxU6XvrkZMyCr4znxvuDxjMk1RGIdO7v+rbBMLEgqtSMNqJbYeVCnj2CFgc3fcTcld"
    "X2uOJDrJb/WRlHulthCh"
)

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAx4RgE2luCoRNt/u56x+Ixcd8i6vTo2hLOVwC6nivu9/OTZS4
2twxPwzvZhoZ3ffmwMt/RCk97E1evll0OMg9E7xBMlBDLY1pEhJulN9vgg2kt01v
7zwVDHiUMKvmHXIn9VJZ6V6ww02pg9AFPVWhLx6vtxwJIqap9ExqSjjemqpOL2rg
8aF0rFeU1wVa8T/8ux6TDqVOBlFrGmmnAUyijZ1GkAeFH5b8nWjyVLsHWglCRkzI
24Vq41Xyvo7JbHkj8VOl765GTMgq+M58b7g8YzJNURiHTu7/q2wTCxIKrUjDaiW2
HlQp49ghYHN33E3JXV9rjiQ6yW/1kZR7pbYQoQIDAQABAoIBAQC8KJ0q8Wzzwh5B
esa1dQHZ8+4DEsL/Amae66VcVwD0X3cCN1W2IZ7X5W0Ij2kBqr8V51RYhcR+S+Ek
BtzSiBUBvbKGrqcMGKaUgomDIMzai99hd0gvCCyZnEW1OQhFkNkaRNXCfqiZJ27M
fqvSUiU2eOwh9fCvmxoA6Of8o3FbzcJ+1GMcobWRllDtLmj6lgVbDzuA+0jC5daB
9Tj1pBzu3wn3ufxiS+gBnJ+7NcXH3E73lqCcPa2ufbZ1haxfiGCnRIhFXuQDgxFX
vKdEfDgtvas6r1ahGbc+b/q8E8fZT7cABuIU4yfOORK+MhpyWbvoyyzuVGKj3PKt
KSPJu5CZAoGBAOkoJfAVyYteqKcmGTanGqQnAY43CaYf6GdSPX/jg+JmKZg0zqMC
jWZUtPb93i+jnOInbrnuHOiHAxI8wmhEPed28H2lC/LU8PzlqFkZXKFZ4vLOhhRB
/HeHCFIDosPFlohWi3b+GAjD7sXgnIuGmnXWe2ea/TS3yersifDEoKKjAoGBANsQ
gJX2cJv1c3jhdgcs8vAt5zIOKcCLTOr/QPmVf/kxjNgndswcKHwsxE/voTO9q+TF
v/6yCSTxAdjuKz1oIYWgi/dZo82bBKWxNRpgrGviU3/zwxiHlyIXUhzQu78q3VS/
7S1XVbc7qMV++XkYKHPVD+nVG/gGzFxumX7MLXfrAoGBAJit9cn2OnjNj9uFE1W6
r7N254ndeLAUjPe73xH0RtTm2a4WRopwjW/JYIetTuYbWgyujc+robqTTuuOZjAp
H/CG7o0Ym251CypQqaFO/l2aowclPp/dZhpPjp9GSjuxFBZLtiBB3DNBOwbRQzIK
/vLTdRQvZkgzYkI4i0vjNt3JAoGBANP8HSKBLymMlShlrSx2b8TB9tc2Y2riohVJ
2ttqs0M2kt/dGJWdrgOz4mikL+983Olt/0P9juHDoxEEMK2kpcPEv40lnmBpYU7h
s8yJvnBLvJe2EJYdJ8AipyAhUX1FgpbvfxmASP8eaUxsegeXvBWTGWojAoS6N2o+
0KSl+l3vAoGAFqm0gO9f/Q1Se60YQd4l2PZeMnJFv0slpgHHUwegmd6wJhOD7zJ1
CkZcXwiv7Nog7AI9qKJEUXLjoqL+vJskBzSOqU3tcd670YQMi1aXSXJqYE202K7o
EddTrx3TNpr1D5m/f+6mnXWrc8u9y1+GNx9yz889xMjIBTBI9KqaaOs=
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
