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

_string_with_symbols = (
    string.digits + string.ascii_letters + ".,;:^&*-_+=#~@"
)


def random_string(length):
    return ''.join(random.choice(string.ascii_letters) for _ in xrange(length))


def random_string_with_symbols(length):
    return ''.join(
        random.choice(_string_with_symbols) for _ in xrange(length)
    )


def is_ascii(s):
    try:
        s.encode("ascii")
    except UnicodeEncodeError:
        return False
    except UnicodeDecodeError:
        return False
    else:
        return True
