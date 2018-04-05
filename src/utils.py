import binascii
import itertools
import random
import struct
from constants import *

# String utils
def find_nth(string, substring, n):
    parts = string.split(substring, n + 1)

    if len(parts) <= n + 1:
        return -1

    return len(string) - len(parts[-1]) - len(substring)


def n_first(s, n):
    return s[:n]


def n_last(s, n):
    return s[n:]


# Output Formatting
def newline(n = 1):
    for i in xrange(n):
        print("")

def delimiter():
        print (purple("#") + cyan("#")) * 30

def red(s):
    if not config.get("is_clear"):
        return str("{0}{1}{2}".format(Constants.RED, s, Constants.NONE))
    return s


def green(s):
    if not config.get("is_clear"):
        return str("{0}{1}{2}".format(Constants.GREEN, s, Constants.NONE))
    return s


def yellow(s):
    if not config.get("is_clear"):
        return str("{0}{1}{2}".format(Constants.YELLOW, s, Constants.NONE))
    return s


def blue(s):
    if not config.get("is_clear"):
        return str("{0}{1}{2}".format(Constants.BLUE, s, Constants.NONE))
    return s


def purple(s):
    if not config.get("is_clear"):
        return str("{0}{1}{2}".format(Constants.PURPLE, s, Constants.NONE))
    return s


def cyan(s):
    if not config.get("is_clear"):
        return str("{0}{1}{2}".format(Constants.CYAN, s, Constants.NONE))
    return s


def white(s):
    if not config.get("is_clear"):
        return str("{0}{1}{2}".format(Constants.WHITE, s, Constants.NONE))
    return s


def debug(s=""):
    if config.get("is_debug"):
        print("{0} {1}".format(purple("[ ]   DEBUG  "), s))


def infos(s):
    print("{0} {1}".format("[ ]   INFOS  ", s))


def warning(s):
    print("{0} {1}".format(yellow("[!] WARNING  "), s))


def fail(s):
    print("{0} {1}".format(red("[-]    FAIL  "), s))


def success(s):
    print("{0} {1}".format(green("[+] SUCCESS  "), s))


def end(msg=None):
    debug()
    if msg:
        debug("Program terminated ({0}).".format(msg))
    else:
        debug("Program terminated.")

    exit(0)

def smth_went_wrong(function, error, level=Constants.DEBUG):
    msg = "Something went wrong in {0}: {1}".format(function, error)
    if level == Constants.CRITICAL:
        fail(msg)
        exit(-1)

    elif level == Constants.FAIL:
        fail(msg)

    elif level == Constants.WARNING:
        warning(msg)

    elif level == Constants.DEBUG:
        debug(msg)

