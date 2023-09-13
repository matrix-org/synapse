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

from typing import Callable, Optional, Tuple, Type

import mypy.types
from mypy.erasetype import remove_instance_last_known_values
from mypy.errorcodes import ErrorCode
from mypy.nodes import ARG_NAMED_OPT
from mypy.plugin import MethodSigContext, Plugin
from mypy.typeops import bind_self
from mypy.types import (
    AnyType,
    CallableType,
    Instance,
    NoneType,
    TupleType,
    TypeAliasType,
    UninhabitedType,
    UnionType,
)


class SynapsePlugin(Plugin):
    def get_method_signature_hook(
        self, fullname: str
    ) -> Optional[Callable[[MethodSigContext], CallableType]]:
        if fullname.startswith(
            (
                "synapse.util.caches.descriptors.CachedFunction.__call__",
                "synapse.util.caches.descriptors._LruCachedFunction.__call__",
            )
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

    # 1. Mark this as a bound function signature.
    signature: CallableType = bind_self(ctx.default_signature)

    # 2. Remove any "cache_context" args.
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

    # 3. Add an optional "on_invalidate" argument.
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

    # 4. Ensure the return type is a Deferred.
    if (
        isinstance(signature.ret_type, Instance)
        and signature.ret_type.type.fullname == "twisted.internet.defer.Deferred"
    ):
        # If it is already a Deferred, nothing to do.
        ret_type = signature.ret_type
    else:
        ret_arg = None
        if isinstance(signature.ret_type, Instance):
            # If a coroutine, wrap the coroutine's return type in a Deferred.
            if signature.ret_type.type.fullname == "typing.Coroutine":
                ret_arg = signature.ret_type.args[2]

            # If an awaitable, wrap the awaitable's final value in a Deferred.
            elif signature.ret_type.type.fullname == "typing.Awaitable":
                ret_arg = signature.ret_type.args[0]

        # Otherwise, wrap the return value in a Deferred.
        if ret_arg is None:
            ret_arg = signature.ret_type

        # This should be able to use ctx.api.named_generic_type, but that doesn't seem
        # to find the correct symbol for anything more than 1 module deep.
        #
        # modules is not part of CheckerPluginInterface. The following is a combination
        # of TypeChecker.named_generic_type and TypeChecker.lookup_typeinfo.
        sym = ctx.api.modules["twisted.internet.defer"].names.get("Deferred")  # type: ignore[attr-defined]
        ret_type = Instance(sym.node, [remove_instance_last_known_values(ret_arg)])

    signature = signature.copy_modified(
        arg_types=arg_types,
        arg_names=arg_names,
        arg_kinds=arg_kinds,
        ret_type=ret_type,
    )

    # 5. Complain loudly if we are returning something mutable
    check_is_cacheable(signature, ctx, ret_type)

    return signature


def check_is_cacheable(
    signature: CallableType,
    ctx: MethodSigContext,
    deferred_return_type: Instance,
) -> None:
    # The previous code wraps the return type into a Deferred.
    assert deferred_return_type.type.fullname == "twisted.internet.defer.Deferred"
    return_type = deferred_return_type.args[0]

    verbose = ctx.api.options.verbosity >= 1
    # TODO Technically a cachedList only needs immutable values, but forcing them
    # to return Mapping instead of Dict is fine.
    ok, note = is_cacheable(return_type, signature, verbose)

    if ok:
        message = f"function {signature.name} is @cached, returning {return_type}"
    else:
        message = f"function {signature.name} is @cached, but has mutable return value {return_type}"

    if note:
        message += f" ({note})"
    message = message.replace("builtins.", "").replace("typing.", "")

    # TODO The context is the context of the caller, not the method itself.
    if ok and note:
        ctx.api.note(message, ctx.context)  # type: ignore[attr-defined]
    elif not ok:
        ctx.api.fail(message, ctx.context, code=AT_CACHED_MUTABLE_RETURN)


# Immutable simple values.
IMMUTABLE_VALUE_TYPES = {
    "builtins.bool",
    "builtins.int",
    "builtins.float",
    "builtins.str",
    "builtins.bytes",
}

# Types defined in Synapse which are known to be immutable.
IMMUTABLE_CUSTOM_TYPES = {
    "synapse.synapse_rust.push.FilteredPushRules",
}

# Immutable containers only if the values are also immutable.
IMMUTABLE_CONTAINER_TYPES_REQUIRING_IMMUTABLE_ELEMENTS = {
    "builtins.frozenset",
    "builtins.tuple",
    "typing.AbstractSet",
    "typing.Sequence",
}

MUTABLE_CONTAINER_TYPES = {
    "builtins.set",
    "builtins.list",
    "builtins.dict",
}

AT_CACHED_MUTABLE_RETURN = ErrorCode(
    "synapse-@cached-mutable",
    "@cached() should have an immutable return type",
    "General",
)


def is_cacheable(
    rt: mypy.types.Type, signature: CallableType, verbose: bool
) -> Tuple[bool, Optional[str]]:
    """
    Returns: a 2-tuple (cacheable, message).
        - cachable: False means the type is definitely not cacheable;
            true means anything else.
        - Optional message.
    """

    # This should probably be done via a TypeVisitor. Apologies to the reader!
    if isinstance(rt, AnyType):
        return True, ("may be mutable" if verbose else None)

    elif isinstance(rt, Instance):
        if (
            rt.type.fullname in IMMUTABLE_VALUE_TYPES
            or rt.type.fullname in IMMUTABLE_CUSTOM_TYPES
        ):
            return True, None

        elif rt.type.fullname == "typing.Mapping":
            return is_cacheable(rt.args[1], signature, verbose)

        elif rt.type.fullname in IMMUTABLE_CONTAINER_TYPES_REQUIRING_IMMUTABLE_ELEMENTS:
            # E.g. Collection[T] is cachable iff T is cachable.
            return is_cacheable(rt.args[0], signature, verbose)

        elif rt.type.fullname in MUTABLE_CONTAINER_TYPES:
            return False, None

        elif "attrs" in rt.type.metadata:
            frozen = rt.type.metadata["attrs"].get("frozen", False)
            if frozen:
                # TODO: should really check that all of the fields are also cacheable
                return True, None
            else:
                return False, "non-frozen attrs class"

        else:
            return False, f"Don't know how to handle {rt.type.fullname}"

    elif isinstance(rt, NoneType):
        return True, None

    elif isinstance(rt, (TupleType, UnionType)):
        for item in rt.items:
            ok, note = is_cacheable(item, signature, verbose)
            if not ok:
                return False, note
        # This discards notes but that's probably fine
        return True, None

    elif isinstance(rt, TypeAliasType):
        return is_cacheable(mypy.types.get_proper_type(rt), signature, verbose)

    # The tests check what happens if you raise an Exception, so they don't return.
    elif isinstance(rt, UninhabitedType) and rt.is_noreturn:
        # There's no return value, just consider it cachable.
        return True, None

    else:
        return False, f"Don't know how to handle {type(rt).__qualname__} return type"


def plugin(version: str) -> Type[SynapsePlugin]:
    # This is the entry point of the plugin, and lets us deal with the fact
    # that the mypy plugin interface is *not* stable by looking at the version
    # string.
    #
    # However, since we pin the version of mypy Synapse uses in CI, we don't
    # really care.
    return SynapsePlugin
