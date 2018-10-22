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

from six import PY3
from six.moves import range

_string_with_symbols = (
    string.digits + string.ascii_letters + ".,;:^&*-_+=#~@"
)


def random_string(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


def random_string_with_symbols(length):
    return ''.join(
        random.choice(_string_with_symbols) for _ in range(length)
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
