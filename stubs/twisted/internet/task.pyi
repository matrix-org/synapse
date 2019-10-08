from twisted.internet.defer import Deferred

from zope.interface import implementer

from .base import DelayedCall
from .interfaces import IReactorTime

from typing import Any, Dict, List

class LoopingCall:
    call = None
    running: bool
    _deferred = None
    interval = None
    _runAtStart = False
    starttime = None

    clock: IReactorTime
    f: Any
    a: List
    kw: Dict
    def __init__(self, f, *a, **kw): ...
    @classmethod
    def withCount(cls, countCallable) -> LoopingCall: ...
    def start(self, interval: float, now: bool = True) -> Deferred: ...
    def stop(self): ...
    def reset(self): ...
    def __call__(self): ...
    def _scheduleFrom(self, when: float): ...

class SchedulerError(Exception):
    """
    The operation could not be completed because the scheduler or one of its
    tasks was in an invalid state.  This exception should not be raised
    directly, but is a superclass of various scheduler-state-related
    exceptions.
    """

class SchedulerStopped(SchedulerError):
    """
    The operation could not complete because the scheduler was stopped in
    progress or was already stopped.
    """

class TaskFinished(SchedulerError):
    """
    The operation could not complete because the task was already completed,
    stopped, encountered an error or otherwise permanently stopped running.
    """

class TaskDone(TaskFinished):
    """
    The operation could not complete because the task was already completed.
    """

class TaskStopped(TaskFinished):
    """
    The operation could not complete because the task was stopped.
    """

class TaskFailed(TaskFinished):
    """
    The operation could not complete because the task died with an unhandled
    error.
    """

class NotPaused(SchedulerError):
    """
    This exception is raised when a task is resumed which was not previously
    paused.
    """

class CooperativeTask(object):
    def __init__(self, iterator, cooperator: Cooperator): ...
    def whenDone(self) -> Deferred: ...
    def pause(self): ...
    def resume(self): ...
    def stop(self): ...

class Cooperator(object):
    def __init__(
        self, terminationPredicateFactory=None, scheduler=None, started=True
    ): ...
    def coiterate(self, iterator, doneDeferred=None) -> Deferred: ...
    def cooperate(self, iterator) -> CooperativeTask: ...
    def start(self): ...
    def stop(self): ...
    @property
    def running(self) -> bool: ...

def coiterate(iterator) -> Deferred: ...
def cooperate(iterator) -> CooperativeTask: ...
@implementer(IReactorTime)
class Clock:
    """
    Provide a deterministic, easily-controlled implementation of
    L{IReactorTime.callLater}.  This is commonly useful for writing
    deterministic unit tests for code which schedules events using this API.
    """

    rightNow: float = 0.0
    calls: List[DelayedCall]
    def seconds(self) -> float: ...
    def callLater(self, delay, callable, *a, **kw): ...
    def getDelayedCalls(self) -> List[DelayedCall]: ...
    def advance(self, amount: float): ...
    def pump(self, timings): ...

def deferLater(
    clock: IReactorTime, delay: float, callable=None, *args, **kw
) -> Deferred: ...
def react(main, argv=(), _reactor=None): ...
