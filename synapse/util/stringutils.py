# -*- coding: utf-8 -*-
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

import random
import string

import six
from six import PY2, PY3
from six.moves import range

_string_with_symbols = (
    string.digits + string.ascii_letters + ".,;:^&*-_+=#~@"
)

# random_string and random_string_with_symbols are used for a range of things,
# some cryptographically important, some less so. We use SystemRandom to make sure
# we get cryptographically-secure randoms.
rand = random.SystemRandom()


def random_string(length):
    return ''.join(rand.choice(string.ascii_letters) for _ in range(length))


def random_string_with_symbols(length):
    return ''.join(
        rand.choice(_string_with_symbols) for _ in range(length)
    )


def is_ascii(s):

    if PY3:
        if isinstance(s, bytes):
            try:
                s.decode('ascii').encode('ascii')
            except UnicodeDecodeError:
                return False
            except UnicodeEncodeError:
                return False
            return True

    try:
        s.encode("ascii")
    except UnicodeEncodeError:
        return False
    except UnicodeDecodeError:
        return False
    else:
        return True


def to_ascii(s):
    """Converts a string to ascii if it is ascii, otherwise leave it alone.

    If given None then will return None.
    """
    if PY3:
        return s

    if s is None:
        return None

    try:
        return s.encode("ascii")
    except UnicodeEncodeError:
        return s


def exception_to_unicode(e):
    """Helper function to extract the text of an exception as a unicode string

    Args:
        e (Exception): exception to be stringified

    Returns:
        unicode
    """
    # urgh, this is a mess. The basic problem here is that psycopg2 constructs its
    # exceptions with PyErr_SetString, with a (possibly non-ascii) argument. str() will
    # then produce the raw byte sequence. Under Python 2, this will then cause another
    # error if it gets mixed with a `unicode` object, as per
    # https://github.com/matrix-org/synapse/issues/4252

    # First of all, if we're under python3, everything is fine because it will sort this
    # nonsense out for us.
    if not PY2:
        return str(e)

    # otherwise let's have a stab at decoding the exception message. We'll circumvent
    # Exception.__str__(), which would explode if someone raised Exception(u'non-ascii')
    # and instead look at what is in the args member.

    if len(e.args) == 0:
        return u""
    elif len(e.args) > 1:
        return six.text_type(repr(e.args))

    msg = e.args[0]
    if isinstance(msg, bytes):
        return msg.decode('utf-8', errors='replace')
    else:
        return msg
