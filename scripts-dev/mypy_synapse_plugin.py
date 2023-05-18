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

from typing import Callable, Optional, Type

from mypy.nodes import ARG_NAMED_OPT
from mypy.plugin import MethodSigContext, Plugin
from mypy.typeops import bind_self
from mypy.types import CallableType, NoneType, UnionType


class SynapsePlugin(Plugin):
    def get_method_signature_hook(
        self, fullname: str
    ) -> Optional[Callable[[MethodSigContext], CallableType]]:
        if fullname.startswith(
            "synapse.util.caches.descriptors.CachedFunction.__call__"
        ) or fullname.startswith(
            "synapse.util.caches.descriptors._LruCachedFunction.__call__"
        ):
            return cached_function_method_signature
        return None


def cached_function_method_signature(ctx: MethodSigContext) -> CallableType:
    """Fixes the `CachedFunction.__call__` signature to be correct.

    It already has *almost* the correct signature, except:

        1. the `self` argument needs to be marked as "bound";
        2. any `cache_context` argument should be removed;
        3. an optional keyword argument `on_invalidated` should be added.
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

    arg_types = list(signature.arg_types)
    arg_names = list(signature.arg_names)
    arg_kinds = list(signature.arg_kinds)

    if context_arg_index:
        arg_types.pop(context_arg_index)
        arg_names.pop(context_arg_index)
        arg_kinds.pop(context_arg_index)

    # Third, we add an optional "on_invalidate" argument.
    #
    # This is a either
    # - a callable which accepts no input and returns nothing, or
    # - None.
    calltyp = UnionType(
        [
            NoneType(),
            CallableType(
                arg_types=[],
                arg_kinds=[],
                arg_names=[],
                ret_type=NoneType(),
                fallback=ctx.api.named_generic_type("builtins.function", []),
            ),
        ]
    )

    arg_types.append(calltyp)
    arg_names.append("on_invalidate")
    arg_kinds.append(ARG_NAMED_OPT)  # Arg is an optional kwarg.

    signature = signature.copy_modified(
        arg_types=arg_types,
        arg_names=arg_names,
        arg_kinds=arg_kinds,
    )

    return signature


def plugin(version: str) -> Type[SynapsePlugin]:
    # This is the entry point of the plugin, and lets us deal with the fact
    # that the mypy plugin interface is *not* stable by looking at the version
    # string.
    #
    # However, since we pin the version of mypy Synapse uses in CI, we don't
    # really care.
    return SynapsePlugin
