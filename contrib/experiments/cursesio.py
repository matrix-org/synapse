# Copyright 2014-2016 OpenMarket Ltd
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

import curses
import curses.wrapper
from curses.ascii import isprint

from twisted.internet import reactor


class CursesStdIO():
    def __init__(self, stdscr, callback=None):
        self.statusText = "Synapse test app -"
        self.searchText = ''
        self.stdscr = stdscr

        self.logLine = ''

        self.callback = callback

        self._setup()

    def _setup(self):
        self.stdscr.nodelay(1)  # Make non blocking

        self.rows, self.cols = self.stdscr.getmaxyx()
        self.lines = []

        curses.use_default_colors()

        self.paintStatus(self.statusText)
        self.stdscr.refresh()

    def set_callback(self, callback):
        self.callback = callback

    def fileno(self):
        """ We want to select on FD 0 """
        return 0

    def connectionLost(self, reason):
        self.close()

    def print_line(self, text):
        """ add a line to the internal list of lines"""

        self.lines.append(text)
        self.redraw()

    def print_log(self, text):
        self.logLine = text
        self.redraw()

    def redraw(self):
        """ method for redisplaying lines
            based on internal list of lines """

        self.stdscr.clear()
        self.paintStatus(self.statusText)
        i = 0
        index = len(self.lines) - 1
        while i < (self.rows - 3) and index >= 0:
            self.stdscr.addstr(self.rows - 3 - i, 0, self.lines[index],
                               curses.A_NORMAL)
            i = i + 1
            index = index - 1

        self.printLogLine(self.logLine)

        self.stdscr.refresh()

    def paintStatus(self, text):
        if len(text) > self.cols:
            raise RuntimeError("TextTooLongError")

        self.stdscr.addstr(
            self.rows - 2, 0,
            text + ' ' * (self.cols - len(text)),
            curses.A_STANDOUT)

    def printLogLine(self, text):
        self.stdscr.addstr(
            0, 0,
            text + ' ' * (self.cols - len(text)),
            curses.A_STANDOUT)

    def doRead(self):
        """ Input is ready! """
        curses.noecho()
        c = self.stdscr.getch()  # read a character

        if c == curses.KEY_BACKSPACE:
            self.searchText = self.searchText[:-1]

        elif c == curses.KEY_ENTER or c == 10:
            text = self.searchText
            self.searchText = ''

            self.print_line(">> %s" % text)

            try:
                if self.callback:
                    self.callback.on_line(text)
            except Exception as e:
                self.print_line(str(e))

            self.stdscr.refresh()

        elif isprint(c):
            if len(self.searchText) == self.cols - 2:
                return
            self.searchText = self.searchText + chr(c)

        self.stdscr.addstr(self.rows - 1, 0,
                           self.searchText + (' ' * (
                           self.cols - len(self.searchText) - 2)))

        self.paintStatus(self.statusText + ' %d' % len(self.searchText))
        self.stdscr.move(self.rows - 1, len(self.searchText))
        self.stdscr.refresh()

    def logPrefix(self):
        return "CursesStdIO"

    def close(self):
        """ clean up """

        curses.nocbreak()
        self.stdscr.keypad(0)
        curses.echo()
        curses.endwin()


class Callback(object):

    def __init__(self, stdio):
        self.stdio = stdio

    def on_line(self, text):
        self.stdio.print_line(text)


def main(stdscr):
    screen = CursesStdIO(stdscr)   # create Screen object

    callback = Callback(screen)

    screen.set_callback(callback)

    stdscr.refresh()
    reactor.addReader(screen)
    reactor.run()
    screen.close()


if __name__ == '__main__':
    curses.wrapper(main)
