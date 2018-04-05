IOCTL PEELER
============

Objective is to analyze IOCTLs from various kernel modules, and determine which
constraints are applied on them in order to get a full list of valid IOCTL commands.

This won't work at all, since it required some special version of angr and my own modified version of CLE. So it's just there to give an idea of what I was doing.

Requirements
============

Custom version of CLE
angr

Usage
=====

```console
./pyfinder -q MODULE.ko
```

Options
=======

```python
"""
Check if argument is an existing file, and setup script env

Arguments:
-q/--quiet:    Remove debug messages
-v/--verbose:  Activate angr loggers
-c/--no_color: Don't put colors in outputs (for parsing)
-f/--function: Analyze a specific function
-l/--log     : Enable loggings to the directory specified as parameter
-i/--ida     : Offset to substract to outputed addresses, so that it matches IDA
-s/--source  : Source header to extract ioctl commands from
"""
```
