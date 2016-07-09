###############################################################################
#
# The MIT License (MIT)
#
# Copyright (c) Tavendo GmbH
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
###############################################################################

import os
import time
import sys
import re
import base64
import math


__all__ = ("newid",
           "rtime",
           "Stopwatch")


# Note on the ID range [0, 2**53]. We once reduced the range to [0, 2**31].
# This lead to extremely hard to track down issues due to ID collisions!
# Here: https://github.com/crossbario/autobahn-python/issues/419#issue-90483337
#

def newid(length=16):
    """
    Generate a new random string ID.

    The generated ID is uniformly distributed and cryptographically strong. It is
    hence usable for things like secret keys and access tokens.

    :param length: The length (in chars) of the ID to generate.
    :type length: int

    :returns: A random string ID.
    :rtype: unicode
    """
    l = int(math.ceil(float(length) * 6. / 8.))
    return base64.b64encode(os.urandom(l))[:length].decode('ascii')


# Select the most precise walltime measurement function available
# on the platform
#
if sys.platform.startswith('win'):
    # On Windows, this function returns wall-clock seconds elapsed since the
    # first call to this function, as a floating point number, based on the
    # Win32 function QueryPerformanceCounter(). The resolution is typically
    # better than one microsecond
    _rtime = time.clock
    _ = _rtime()  # this starts wallclock
else:
    # On Unix-like platforms, this used the first available from this list:
    # (1) gettimeofday() -- resolution in microseconds
    # (2) ftime() -- resolution in milliseconds
    # (3) time() -- resolution in seconds
    _rtime = time.time


rtime = _rtime
"""
Precise wallclock time.

:returns: The current wallclock in seconds. Returned values are only guaranteed
   to be meaningful relative to each other.
:rtype: float
"""


class Stopwatch(object):
    """
    Stopwatch based on walltime.

    This can be used to do code timing and uses the most precise walltime measurement
    available on the platform. This is a very light-weight object,
    so create/dispose is very cheap.
    """

    def __init__(self, start=True):
        """
        :param start: If ``True``, immediately start the stopwatch.
        :type start: bool
        """
        self._elapsed = 0
        if start:
            self._started = rtime()
            self._running = True
        else:
            self._started = None
            self._running = False

    def elapsed(self):
        """
        Return total time elapsed in seconds during which the stopwatch was running.

        :returns: The elapsed time in seconds.
        :rtype: float
        """
        if self._running:
            now = rtime()
            return self._elapsed + (now - self._started)
        else:
            return self._elapsed

    def pause(self):
        """
        Pauses the stopwatch and returns total time elapsed in seconds during which
        the stopwatch was running.

        :returns: The elapsed time in seconds.
        :rtype: float
        """
        if self._running:
            now = rtime()
            self._elapsed += now - self._started
            self._running = False
            return self._elapsed
        else:
            return self._elapsed

    def resume(self):
        """
        Resumes a paused stopwatch and returns total elapsed time in seconds
        during which the stopwatch was running.

        :returns: The elapsed time in seconds.
        :rtype: float
        """
        if not self._running:
            self._started = rtime()
            self._running = True
            return self._elapsed
        else:
            now = rtime()
            return self._elapsed + (now - self._started)

    def stop(self):
        """
        Stops the stopwatch and returns total time elapsed in seconds during which
        the stopwatch was (previously) running.

        :returns: The elapsed time in seconds.
        :rtype: float
        """
        elapsed = self.pause()
        self._elapsed = 0
        self._started = None
        self._running = False
        return elapsed


def wildcards2patterns(wildcards):
    """
    Compute a list of regular expression patterns from a list of
    wildcard strings. A wildcard string uses '*' as a wildcard character
    matching anything.

    :param wildcards: List of wildcard strings to compute regular expression patterns for.
    :type wildcards: list of str
    :returns: Computed regular expressions.
    :rtype: list of obj
    """
    return [re.compile(wc.replace('.', '\.').replace('*', '.*')) for wc in wildcards]


def makeHttpResp(html, type_='text/html'):
    body = html.encode('utf8')
    header = ["HTTP/1.1 200 OK",
              "Content-Type: %s; charset=UTF-8" % type_,
              "Content-Length: %d" % len(body)]
    return "\r\n".join(header).encode("utf-8") + b"\r\n\r\n" + body
