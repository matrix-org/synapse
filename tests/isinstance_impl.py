# Per https://github.com/Shoobx/mypy-zope/pull/92#issuecomment-1483266683
from typing import Optional
from zope.interface import implementer, Interface


class IFoo(Interface):
    ...


@implementer(IFoo)
class MyFoo:
    ...


def make_foo() -> Optional[IFoo]:
    return MyFoo()


x = make_foo()
reveal_type(x)
assert isinstance(x, MyFoo)

# The code below should not be considered unreachable
print("hello")

"""
<output>
isinstance_impl.py:19: note: Revealed type is "Union[__main__.IFoo, None]"
</output>
"""
