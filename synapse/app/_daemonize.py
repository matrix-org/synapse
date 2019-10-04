# -*- coding: utf-8 -*
# HEAVILY "inspired" by https://github.com/thesharp/daemonize/blob/master/daemonize.py
# TODO: License header
# app, pid, action, autoclose, verbose, logger, 


import fcntl
import os
import pwd
import grp
import sys
import signal
import resource
import logging
import atexit
from logging import handlers
import traceback


__version__ = "2.5.0"


class Daemonize2(object):
    """
    Daemonize object.

    Object constructor expects three arguments.

    :param app: contains the application name which will be sent to syslog.
    :param pid: path to the pidfile.
    :param action: your custom function which will be executed after daemonization.
    :param verbose: send debug messages to logger if provided.
    :param logger: use this logger object instead of creating new one, if provided.
    :param chdir: change working directory if provided or /
    """
    def __init__(self, app, pid, action,
                 keep_fds=None, auto_close_fds=True, privileged_action=None,
                 user=None, group=None, verbose=False, logger=None,
                 foreground=False, chdir="/", outfile="homeserver.out"):
        self.app = app
        self.pid = os.path.abspath(pid)
        self.outfile = os.path.abspath(outfile)
        self.action = action
        self.logger = logger
        self.verbose = verbose
        self.chdir = chdir

    def sigterm(self, signum, frame):
        """
        These actions will be done after SIGTERM.
        """
        self.logger.warning("Caught signal %s. Stopping daemon." % signum)
        sys.exit(0)

    def exit(self):
        """
        Cleanup pid file at exit.
        """
        self.logger.warning("Stopping daemon.")
        os.remove(self.pid)
        sys.exit(0)

    def start(self):
        """
        Start daemonization process.
        """
        # If pidfile already exists, we should read pid from there; to overwrite it, if locking
        # will fail, because locking attempt somehow purges the file contents.
        if os.path.isfile(self.pid):
            with open(self.pid, "r") as old_pidfile:
                old_pid = old_pidfile.read()
        # Create a lockfile so that only one instance of this daemon is running at any time.
        try:
            lockfile = open(self.pid, "w")
        except IOError:
            print("Unable to create the pidfile.")
            sys.exit(1)
        try:
            # Try to get an exclusive lock on the file. This will fail if another process has the file
            # locked.
            fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            print("Unable to lock on the pidfile.")
            # We need to overwrite the pidfile if we got here.
            with open(self.pid, "w") as pidfile:
                pidfile.write(old_pid)
            sys.exit(1)

        # Fork, creating a new process for the child.
        try:
            process_id = os.fork()
        except OSError as e:
            self.logger.error("Unable to fork, errno: {0}".format(e.errno))
            sys.exit(1)
        if process_id != 0:
            sys.exit(0)

        # This is the child process. Continue.

        # Stop listening for signals that the parent process receives.
        # This is done by getting a new process id.
        # setpgrp() is an alternative to setsid().
        # setsid puts the process in a new parent group and detaches its controlling terminal.
        process_id = os.setsid()
        if process_id == -1:
            # Uh oh, there was a problem.
            sys.exit(1)

        with open(self.outfile, 'w+') as f:
            os.dup2(f.fileno(), 2)
            os.dup2(f.fileno(), 1)



        # Set umask to default to safe file permissions when running as a root daemon. 027 is an
        # octal number which we are typing as 0o27 for Python3 compatibility.
        os.umask(0o27)

        # Change to a known directory. If this isn't done, starting a daemon in a subdirectory that
        # needs to be deleted results in "directory busy" errors.
        os.chdir(self.chdir)

        try:
            lockfile.write("%s" % (os.getpid()))
            lockfile.flush()
        except IOError:
            self.logger.error("Unable to write pid to the pidfile.")
            print("Unable to write pid to the pidfile.")
            sys.exit(1)

        # Set custom action on SIGTERM.
        signal.signal(signal.SIGTERM, self.sigterm)
        atexit.register(self.exit)

        self.logger.warning("Starting daemon.")

        print("################## PRINTED TO STDERR FROM _daemonize!!!!!!!!!", file=sys.stderr)

        try:
            self.action()
        except Exception:
            for line in traceback.format_exc().split("\n"):
                self.logger.error(line)
