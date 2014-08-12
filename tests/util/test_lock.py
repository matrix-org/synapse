# -*- coding: utf-8 -*-

from twisted.internet import defer
from twisted.trial import unittest

from synapse.util.lockutils import LockManager


class LockManagerTestCase(unittest.TestCase):

    def setUp(self):
        self.lock_manager = LockManager()

    @defer.inlineCallbacks
    def test_one_lock(self):
        key = "test"
        deferred_lock1 = self.lock_manager.lock(key)

        self.assertTrue(deferred_lock1.called)

        lock1 = yield deferred_lock1

        self.assertFalse(lock1.released)

        lock1.release()

        self.assertTrue(lock1.released)

    @defer.inlineCallbacks
    def test_concurrent_locks(self):
        key = "test"
        deferred_lock1 = self.lock_manager.lock(key)
        deferred_lock2 = self.lock_manager.lock(key)

        self.assertTrue(deferred_lock1.called)
        self.assertFalse(deferred_lock2.called)

        lock1 = yield deferred_lock1

        self.assertFalse(lock1.released)
        self.assertFalse(deferred_lock2.called)

        lock1.release()

        self.assertTrue(lock1.released)
        self.assertTrue(deferred_lock2.called)

        lock2 = yield deferred_lock2

        lock2.release()

    @defer.inlineCallbacks
    def test_sequential_locks(self):
        key = "test"
        deferred_lock1 = self.lock_manager.lock(key)

        self.assertTrue(deferred_lock1.called)

        lock1 = yield deferred_lock1

        self.assertFalse(lock1.released)

        lock1.release()

        self.assertTrue(lock1.released)

        deferred_lock2 = self.lock_manager.lock(key)

        self.assertTrue(deferred_lock2.called)

        lock2 = yield deferred_lock2

        self.assertFalse(lock2.released)

        lock2.release()

        self.assertTrue(lock2.released)

    @defer.inlineCallbacks
    def test_with_statement(self):
        key = "test"
        with (yield self.lock_manager.lock(key)) as lock:
            self.assertFalse(lock.released)

        self.assertTrue(lock.released)

    @defer.inlineCallbacks
    def test_two_with_statement(self):
        key = "test"
        with (yield self.lock_manager.lock(key)):
            pass

        with (yield self.lock_manager.lock(key)):
            pass