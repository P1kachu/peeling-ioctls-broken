from constants import *
from utils import *
import CppHeaderParser

import os, sys, re

def _sanitize(res):
    return res.replace(')', '').replace(
                       ',', '').replace(
                       ' ', '').replace(
                       '\t', '').replace(
                       "'", '')

def _extract_number(regex, line):
    res = regex.search(line)
    if res:
        return _sanitize(res.group())

    return None



def _extract_commands(defines):
    commands = []
    regex = re.compile(r',[\w ]*[,\)]')
    for line in defines:
        x = _extract_number(regex, line)
        if x:
            commands.append(x)

    return commands

def _match_values(undefined, header):
    ret = []

    try:
        for e in header.enums[0]['values']:
            if e['name'] in undefined:
                ret.append(e['value'])
                undefined = [val for val in undefined if e['name'] not in val]

                if len(undefined) == 0:
                    return ret
    except:
        pass

    regex = re.compile(r"[\w']*$")
    for undef in undefined:
        for define in header.defines:
            if undef in define:
                i = _extract_number(regex, define)
                try:
                    if i.isdigit():
                        i = int(i)
                    else:
                        i = ord(i)
                except Exception as e:
                    #smth_went_wrong('match_values', e, Constants.FAIL)
                    continue

                ret.append(i)
                undefined = [val for val in undefined if undef not in val]

                if len(undefined) == 0:
                    return ret

    return ret


def _extract_numbers(filepath):
    try:
        header = CppHeaderParser.CppHeader(filepath)
    except CppHeaderParser.CppParseError as e:
        print(e)
        sys.exit(1)

    defines = [define for define in header.defines if '_IO' in define]
    commands = _extract_commands(defines)
    undefined = [c for c in commands if not c.isdigit()]
    commands = [command for command in commands if command not in undefined]
    commands += _match_values(undefined, header)
    commands = [int(command) for command in commands]

    return commands


def extract_ioctl_commands(f):
    """
    Header parser (WIP)

    Try to extract IOCTL command numbers from header
    """
    numbers = _extract_numbers(f)
    if len(numbers) > 0:
        debug("{0}: {1}".format(f, numbers))
    return numbers

