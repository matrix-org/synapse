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

from six import binary_type, text_type

from canonicaljson import json
from frozendict import frozendict


def freeze(o):
    if isinstance(o, dict):
        return frozendict({k: freeze(v) for k, v in o.items()})

    if isinstance(o, frozendict):
        return o

    if isinstance(o, (binary_type, text_type)):
        return o

    try:
        return tuple([freeze(i) for i in o])
    except TypeError:
        pass

    return o


def unfreeze(o):
    if isinstance(o, (dict, frozendict)):
        return dict({k: unfreeze(v) for k, v in o.items()})

    if isinstance(o, (binary_type, text_type)):
        return o

    try:
        return [unfreeze(i) for i in o]
    except TypeError:
        pass

    return o


def _handle_frozendict(obj):
    """Helper for EventEncoder. Makes frozendicts serializable by returning
    the underlying dict
    """
    if type(obj) is frozendict:
        # fishing the protected dict out of the object is a bit nasty,
        # but we don't really want the overhead of copying the dict.
        return obj._dict
    raise TypeError(
        "Object of type %s is not JSON serializable" % obj.__class__.__name__
    )


# A JSONEncoder which is capable of encoding frozendics without barfing
frozendict_json_encoder = json.JSONEncoder(default=_handle_frozendict)
