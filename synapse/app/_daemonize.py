# -*- coding: utf-8 -*
# Inspired by https://github.com/thesharp/daemonize/blob/master/daemonize.py
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


import fcntl
import os
import sys
import signal
import resource
import atexit
import traceback

class Daemonize(object):
    """
    Daemonize object.

    Object constructor expects three arguments.

    :param app: contains the application name which will be sent to syslog.
    :param pid: path to the pidfile.
    :param action: your custom function which will be executed after daemonization.
    :param logger: use this logger object instead of creating new one, if provided.
    :param chdir: change working directory if provided or /
    :param outfile: File to 
    :param void_stdio: Should stdio be sent to /dev/null or to outfile
    """
    def __init__(self, app, pid, action,
                 verbose=False, logger=None,
                 chdir="/", outfile="homeserver.out",
                 void_stdio=False):
        self.app = app
        self.pid = os.path.abspath(pid)
        self.outfile = os.path.abspath(outfile)
        self.action = action
        self.logger = logger
        self.chdir = chdir
        self.void_stdio = void_stdio

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

        if self.void_stdio:
            with open(self.outfile, 'w+') as f:
                f.write("***STARTED STDIO REDIRECT FILE")
                os.dup2(f.fileno(), 1)
                os.dup2(f.fileno(), 2)
        else:
            devnull = "/dev/null"
            if hasattr(os, "devnull"):
                # Python has set os.devnull on this system, use it instead as it might be different
                # than /dev/null.
                devnull = os.devnull
            
            devnull_fd = os.open(devnull, os.O_RDWR)
            os.dup2(devnull_fd, 1)
            os.dup2(devnull_fd, 2)
            os.close(devnull_fd)



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


        try:
            self.action()
        except Exception:
            for line in traceback.format_exc().split("\n"):
                self.logger.error(line)
