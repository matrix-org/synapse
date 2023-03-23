from typing import Optional

from zope.interface import Interface, implementer


class IFoo(Interface):
    pass


@implementer(IFoo)
class BaseFoo:
    pass


class ChildFoo(BaseFoo):
    pass


class IFooFactory(Interface):
    def build() -> Optional[IFoo]:
        pass


def build_and_use_foo(client_factory: IFooFactory) -> None:
    client_protocol = client_factory.build()
    assert isinstance(client_protocol, ChildFoo)
    print("Hello")
