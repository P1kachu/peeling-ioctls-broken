import os
import logging
import claripy
import re
from utils import *

def quiet_loggers():
    """
    Shut the 10000 loggers of angr
    """
    for l in logging.Logger.manager.loggerDict:
        logging.getLogger(l).setLevel(logging.CRITICAL)

def reactivate_loggers():
    """
    Reactivate the loggers
    """
    for l in logging.Logger.manager.loggerDict:
        logging.getLogger(l).setLevel(logging.WARNING)

def get_reg(project, offset_name):
    """
    Get reg name from the list of registers
    """
    try:
        return project.arch.register_names[int(offset_name.split("_")[1],16)]

    except:
        return offset_name

def is_logic_op(op):
    return op in logical_ops

def get_logical_op(op, invert = False):
    if op in logical_ops:
        if invert:
            return logical_ops[op][1]
        else:
            return logical_ops[op][0]
    else:
        return "unk_lop{0}".format(op)

def get_op(op):
    """
    Operand pretty printer
    """
    if op in ops:
        return ops[op]
    else:
        return "unk_op{0}".format(op)


def handle_extract(project, ex):
    """
    Dirty hack to handle 'Extract' BVs
    """
    extracted = ex.args[2]

    ret = "{0}[{1}:{2}]"

    if extracted.op == 'BVS':
        return ret.format(get_bv(project, extracted), ex.args[0], ex.args[1])

    return ret.format(print_bool(project, extracted), ex.args[0], ex.args[1])

def get_bv(project, bv):
    """
    BV Pretty printer
    """

    # BV is a number
    if bv.op == 'BVV':
        return "0x{:x}".format(int(bv.args[0]))

    # BV is a register
    elif bv.op == 'BVS':
        return get_reg(project, bv.args[0])

    # BV is an annoying mix
    elif bv.op == 'Extract':
        return handle_extract(project, bv)

    else:
        try:
            return get_op(bv.op)
        except:
            raise ValueError("unk_BV_{0}".format(bv.op))

def print_bool(project, b, invert=False):
    """
    Boolean pretty printer (recursive call)
    """

    # Invert sign of current bool
    try:
        if b.op == 'Not':
            return print_bool(project, b.args[0], True)
    except Exception as e:
        smth_went_wrong('print_bool', e, constants.DEBUG)

    # For each son of the current nod,
    # recursive call or apply conversion
    res = []
    try:
        for arg in b.args:
            if issubclass(type(arg), claripy.ast.bv.BV):
                member = get_bv(project, arg)
            else:
                member = print_bool(project, arg)
            res.append(member)
    except Exception as e:
        smth_went_wrong('print_bool', e, WARNING)

    try:
        # Pretty print operators
        op = ""
        if invert and b.op in ['Or', 'And']:
            res = [ "!({0})".format(s) for s in res ]
            op = get_logical_op(b.op, invert)
        else:
            if is_logic_op(b.op):
                op = get_logical_op(b.op, invert)
            else:
                op = get_op(b.op)
        # And return formatted string
        return " {0} ".format(op).join(res)
    except:
        return str(b)

def pretty_printer(project, eq):
    """
    Expression pretty printer
    """

    # Simplified equations always are
    # a list of one element
    claripy_bool = eq[0]

    # Recursive call
    simplified = print_bool(project, claripy_bool)
    return simplified

def replace_regs(match):
    return get_reg(config['project'], match.string)

def log(simplified_equ, negative_vals, module, ioctl):
    """
    Save values to file
    """
    infos("Wrinting result to {0}/{1}_{2}.log".format(config['log'], module, ioctl))
    directory = config['log']
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open("{0}/{1}_{2}.logs".format(directory, module, ioctl), 'w') as f:
        f.write("{0} Positive return values {0}\n".format('-' * 30))
        pattern = re.compile(r'reg_\d*_\d*_\d*')
        for eq in simplified_equ:
            eq[0][0] = pattern.sub(replace_regs, str(eq[0][0]))
            f.write("{0}: [{1}, {2}]\n".format(eq[0], hex(eq[1]), hex(eq[2])))

        f.write("\n{0} Negative return values {0}\n".format('-' * 30))

        for neg in negative_vals:
            msg = "{0} to {1}: [{2}, {3}]\n"
            f.write(msg.format(hex(neg[0]), hex(neg[1]), hex(neg[2]), hex(neg[3])))

def sanity_check(state, simplified):
    """
    TODO: Verify that commands from header match the expression
    """

    #print(dir(state))
    #print(simplified.args)
    return True

