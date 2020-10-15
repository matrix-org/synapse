# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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

"""This is a mypy plugin for Synpase to deal with some of the funky typing that
can crop up, e.g the cache descriptors.
"""

from typing import Callable, Optional

from mypy.plugin import MethodSigContext, Plugin
from mypy.typeops import bind_self
from mypy.types import CallableType


class SynapsePlugin(Plugin):
    def get_method_signature_hook(
        self, fullname: str
    ) -> Optional[Callable[[MethodSigContext], CallableType]]:
        if fullname.startswith(
            "synapse.util.caches.descriptors._CachedFunction.__call__"
        ):
            return cached_function_method_signature
        return None


def cached_function_method_signature(ctx: MethodSigContext) -> CallableType:
    """Fixes the `_CachedFunction.__call__` signature to be correct.

    It already has *almost* the correct signature, except:

        1. the `self` argument needs to be marked as "bound"; and
        2. any `cache_context` argument should be removed.
    """

    # First we mark this as a bound function signature.
    signature = bind_self(ctx.default_signature)

    # Secondly, we remove any "cache_context" args.
    #
    # Note: We should be only doing this if `cache_context=True` is set, but if
    # it isn't then the code will raise an exception when its called anyway, so
    # its not the end of the world.
    context_arg_index = None
    for idx, name in enumerate(signature.arg_names):
        if name == "cache_context":
            context_arg_index = idx
            break

    if context_arg_index:
        arg_types = list(signature.arg_types)
        arg_types.pop(context_arg_index)

        arg_names = list(signature.arg_names)
        arg_names.pop(context_arg_index)

        arg_kinds = list(signature.arg_kinds)
        arg_kinds.pop(context_arg_index)

        signature = signature.copy_modified(
            arg_types=arg_types, arg_names=arg_names, arg_kinds=arg_kinds,
        )

    return signature


def plugin(version: str):
    # This is the entry point of the plugin, and let's us deal with the fact
    # that the mypy plugin interface is *not* stable by looking at the version
    # string.
    #
    # However, since we pin the version of mypy Synapse uses in CI, we don't
    # really care.
    return SynapsePlugin
