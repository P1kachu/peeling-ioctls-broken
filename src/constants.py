config = {
    'is_verbose': False,
    'is_debug'  : True,
    'is_clear'  : False,
    'log'  : None,
    'project': None,
    'header': None
}

class Constants:
    '''
    Some constant data
    '''

    # Colors
    RED    = '\033[31;1m'
    GREEN  = '\033[32;1m'
    YELLOW = '\033[33;1m'
    BLUE   = '\033[34;1m'
    PURPLE = '\033[35;1m'
    CYAN   = '\033[36;1m'
    WHITE  = '\033[37;1m'
    NONE   = '\033[0m'

    DEBUG    = 0
    WARNING  = 1
    FAIL     = 2
    CRITICAL = 3

    path_types = [
            'avoid',
            'errored',
            'pruned',
            'stashed',
            'unconstrained',
            'unsat'
        ]


    not_interesting = [
            'spilled',
            'avoided',
            'deviating',
            'looping',
            'lost',
            'pruned'
            #'deadended',
            #'errored',
            #'active',
            #'unconstrained'
        ]


    register_functions = [
            '__register_chrdev',
            'misc_register',
            'cdev_init',
        ]



    logical_ops = {
            '__eq__': [ '==', '!=' ],
            '__ne__': [ '!=', '==' ],

            '__ge__': [ '>=', '<' ],
            'SGE'   : [ '>=', '<' ],
            'UGE'   : [ '>=', '<' ],

            '__gt__': [ '>', '<=' ],
            'SGT   ': [ '>', '<=' ],
            'UGT   ': [ '>', '<=' ],

            '__le__': [ '<=', '>' ],
            'SLE'   : [ '<=', '>' ],
            'ULE'   : [ '<=', '>' ],

            '__lt__': [ '<', '>=' ],
            'SLT'   : [ '<', '>=' ],
            'ULT'   : [ '<', '>=' ],

            'And'    : [ '&&', '||' ],
            '__and__': [ '&&', '||' ],
            'Or'     : [ '||', '&&' ],
            '__or__' : [ '||', '&&' ],
        }


    ops = {
        '__add__'    : '+',
        '__mul__'    : '*',
        '__div__'    : '/',
        '__sub__'    : '-',
        '__xor__'    : '^',
        '__lshift__' : '<<',
        '__rshift__' : '>>',
        }


