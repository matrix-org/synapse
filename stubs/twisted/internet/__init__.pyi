from typing import TypeVar

from .interfaces import IReactorCore, IReactorTime

reactor = TypeVar("reactor", IReactorCore, IReactorTime)
