# -*- coding: utf-8 -*-
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

"""
Depedency injectection that copes with dependency cycles.

Usage:
    class A(Injected):
        def __init__(self, context):
            self.b = context.get(B)

    class B(Injected):
        def __init__(self, context):
            self.a = context.get(A)

    context = Registry()
    a = context.get(A)
    b = context.get(B)

    assert a is b.a
    assert b is a.b
"""


class Registry(object):
    """Context mapping from object type to instance for the object instances
    that are injected as dependencies into other objects."""

    def __init__(self):
        self.registry = {}

    def register(self, cls, instance):
        if cls in self.registry and self.registry[cls] is not instance:
            # This will most likely happen if code constructs the class directly
            # rather than getting a copy from the registry.
            raise ValueError("Cannot register duplicate instance of %r", cls)

        self.registry[cls] = instance

    def get(self, cls):
        """Get an instance of the class, constructing one with no arguments if
        necessary."""
        # If the there's an instance registered then use that.
        instance = self.registry.get(cls)
        if instance is None:
            # Otherwise construct an instance.
            instance = cls(self)
            # Bind it to the registry incase the constructor didn't bind it.
            self.registry[cls] = instance
        return instance


class Injected(object):
    """An object that exists as a singleton within a context."""

    def __new__(cls, registry, *args, **kargs):
        # Pass all the arguments to the super class constructor. This is
        # unlikely to be relevant, since most of the types won't overload
        # __new__. So this is probably hitting the default object __new__
        # operator, and that ignores the arguments.
        instance = super(Injected, cls).__new__(cls, registry, *args, **kargs)

        # Add ourselves to the registry. This happens before __init__ is called
        # so anything that tries to get an instance of this from the registry
        # in __init__ will receive this instance rather than constructing a new
        # one.
        registry.register(cls, instance)

        # In theory we could check if there was already an instance of this
        # class in the registry and return that without contructing a new class.
        # However markjh suspects that would be a bit *too* magical.
        return instance
