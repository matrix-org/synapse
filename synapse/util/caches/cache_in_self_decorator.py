from typing import TYPE_CHECKING, Callable, Dict, List, Optional, TypeVar, cast

T = TypeVar("T")


def cache_in_self(builder: Callable[["HomeServer"], T]) -> Callable[["HomeServer"], T]:
    """Wraps a function called e.g. `get_foo`, checking if `self.foo` exists and
    returning if so. If not, calls the given function and sets `self.foo` to it.

    Also ensures that dependency cycles throw an exception correctly, rather
    than overflowing the stack.
    """

    if not builder.__name__.startswith("get_"):
        raise Exception(
            "@cache_in_self can only be used on functions starting with `get_`"
        )

    # get_attr -> _attr
    depname = builder.__name__[len("get") :]

    building = [False]

    @functools.wraps(builder)
    def _get(self: "HomeServer") -> T:
        try:
            return getattr(self, depname)
        except AttributeError:
            pass

        # Prevent cyclic dependencies from deadlocking
        if building[0]:
            raise ValueError("Cyclic dependency while building %s" % (depname,))

        building[0] = True
        try:
            dep = builder(self)
            setattr(self, depname, dep)
        finally:
            building[0] = False

        return dep

    return _get
