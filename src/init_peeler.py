from utils import *
from constants import *
from angr_helpers import *
import argparse
import os

def init():
    """
    Check if argument is an existing file, and setup script env

    Arguments:
    -q/--quiet:    Remove debug messages
    -v/--verbose:  Activate angr loggers
    -c/--no_color: Don't put colors in outputs (for parsing)
    -f/--function: Analyze a specific function
    -l/--log     : Enable loggings to the directory specified as parameter
    -i/--ida     : Offset to substract to outputed addresses, so that it matches
                   IDA
    -s/--source  : Source header to extract ioctl commands from
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('binary')
    parser.add_argument('-q', '--quiet', action='store_true',
            help="Don't display debug messages")
    parser.add_argument('-v', '--verbose', action='store_true',
            help="Reactivate loggers")
    parser.add_argument('-c', '--no_color', action='store_true',
            help="Don't output colors")
    parser.add_argument('-f', '--function',
            help="function to analyze")
    parser.add_argument('-l', '--log',
            help="folder to write logs in")
    parser.add_argument('-i', '--ida',
            help="IDA Offset to substract to addresses for debugging (hex)")
    parser.add_argument('-s', '--source',
            help="Source header to extract ioctl commands from")

    args = vars(parser.parse_args())

    if len(args) < 2:
        fail("USAGE: {0} ELF.ko [options]".format(sys.argv[0]))
        exit(-1)

    if not os.path.isfile(args['binary']):
        fail("{0}: File not found".format(args['binary']))
        exit(-1)

    # Used to match IDA's addresses for debugging and pretty printing
    if args['ida']:
        config['ida_offset'] = int(args['ida'], 16)
    else:
        config['ida_offset'] = 0

    if args['quiet']:
        config['is_debug'] = False

    if args['no_color']:
        config['is_clear'] = True

    if args['verbose']:
        config['is_verbose'] = True
    else:
        # Remove logger messages (for non-debugging sessions)
        quiet_loggers()

    if args['log']:
        config['log'] = args['log']

    if args['source']:
        config['header'] = args['source']


    return args['binary'], args['function']


