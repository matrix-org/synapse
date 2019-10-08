from .interfaces import IReactorCore, IReactorTime

from typing import TypeVar

reactor = TypeVar("reactor", IReactorCore, IReactorTime)
