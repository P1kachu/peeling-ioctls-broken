#!/usr/bin/python2

import pprint
import sys
import angr
import claripy
import simuvex
import cle

from init_peeler import *
from angr_helpers import *
from excavator import *
from header_parser import *

from elfesteem.elf_init import ELF
from elftools.construct.lib.container import Container
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection, Symbol
from inspect import currentframe, getframeinfo

def analyze_paths(p_type, p_list, addr):
    """
    For each path whose category is interesting, get constraints and return
    values.

    The main constraint applied is that the return value should be negative to
    be considered valid.

    :param p_type: Path type
    :param p_list: List of paths
    :param addr:   Address of start (usually start of ioctl)
    :return:       Two lists containing respectively the valid and invalid
                   return values and constraints
    :rtype:        Two lists of tuples
    """

    idaoff = config['ida_offset']

    # Let's save some time by skipping path that won't help us (like the ones
    # that lead nowhere/are empty)
    if len(p_list) <= 0:
        return

    if p_type in Constants.not_interesting:
        if config['is_debug']:
            newline()
            infos("Skipping {0} {1} paths".format(len(p_list), yellow(p_type)))
        return

    newline()

    # Path type is interesting, let's dig
    infos("Analyzing {0} {1} paths".format(len(p_list), yellow(p_type)))

    # We will keep every simplified equation with its minimum and maximum
    # satisfiable value. We will also keep negative values, to be sure
    simplified_equations = []
    negative_values = []

    # For each path, get constraints and return value
    for i, path in enumerate(p_list):

        sat_min = 0
        sat_max = pow(2, project.arch.bits - 1) - 1
        sat_max_32 = pow(2, project.arch.bits / 2) - 1
        state = path.state

        # Get the good register size
        try:
            ax = state.regs.rax
        except:
            smth_went_wrong('analyze_paths', '%rax not found', Constants.WARNING)
            ax = state.regs.eax

        if p_type == 'errored':
            warning("Path errored: {0}".format(path.error))
        elif p_type == 'deadended':
            for step in path.addr_trace:
                debug("  {0}".format(hex(step - idaoff)))

        nb = len(p_list)
        msg = green("Path from {0} to {1} ({2}/{3})")
        infos(msg.format(hex(addr - idaoff), hex(path.addr - idaoff), i+1, nb))

        # Adding constraints regarding the return value. z3 doesn't seem to
        # know what a negative value is.
        constraint = claripy.If(ax >= sat_max_32,
                                ax[project.arch.bits - 1] == 0,
                                ax[project.arch.bits / 2 - 1] == 0)
        state.se.add(constraint)
        try:
            sat_min = state.se.min(ax)
            sat_max = state.se.max(ax)
        except simuvex.s_errors.SimUnsatError as e:
            smth_went_wrong('se.min/max', 'Unsat Error', Constants.FAIL)
            continue

        # Get state simplified equation from constraints
        simplified = state.se.simplify()

        # Debug
        debug("Backtrace:")
        for step in path.addr_trace:
            debug("  {0}".format(hex(step - idaoff)))
        debug("  Required conditions (constraints):")
        for constr in state.se.constraints:
            debug("    {0}".format(constr))

        # return value does not fit the constraints
        if simplified and claripy.is_false(simplified[0]):
                if sat_min == sat_max:
                    msg = "Return value would be {0} - Skipping"
                    infos(msg.format(red(hex(sat_min))))
                else:
                    msg = "Return value would be between {0} and {1} - Skipping"
                    infos(msg.format(red(hex(sat_min)), red(hex(sat_max))))
                negative_values.append([addr, path.addr, sat_min, sat_max])
                continue

        # Print simplified equation
        if simplified:
            debug("Simplified: {0}".format(green(simplified[0])))
        simplified = simplified[0]

        if sat_min == sat_max:
            success("Satisfiable value: {0}".format(hex(sat_min)))
        else:
            success("Min satisfiable value: {0}".format(hex(sat_min)))
            success("Max satisfiable value: {0}".format(hex(sat_max)))


        if not sanity_check(state, simplified):
            smth_went_wrong('analyze_path', 'Sanity check failed', Constants.WARNING)

        simplified_equations.append([simplified, sat_min, sat_max])

    return simplified_equations, negative_values


if __name__ in "__main__":
    """
    IOCTL PEELER

    Find and analyze ioctls to determine which valid arguments can be passed
    """

    # Init
    binary, function = init()
    idaoff = config['ida_offset']
    module = os.path.splitext(os.path.basename(binary))[0]
    infos("Peeling {0}'s ioctls".format(green(module)))

    # Init project
    project = angr.Project(binary)
    config['project'] = project

    # If the user specified a header to take commands from, try it
    if config['header'] is not None:
        config['commands'] = extract_ioctl_commands(config['header'])

    # If the user specified a function to look for, take it from the symbols.
    # Else, try to get ioctls from various ways
    if function is not None:
        ioctls = get_ioctls_from_name(project, [function])

    else:

        ioctls = get_ioctl_from_dwarf(project)
        #exit(0)

        if len(ioctls) < 1:
            # DWARFs unhelpful - Trying fops
            smth_went_wrong('__main__', 'IOCTLs not found with DWARFS', Constants.WARNING)
            ioctls = get_ioctl_from_fops(project)

        if len(ioctls) < 1:
            # fops unhelpful - Trying dumb symbol lookup
            smth_went_wrong('__main__', 'IOCTLs not found with fops', Constants.WARNING)
            ioctls = get_ioctls_from_name(project)

        if len(ioctls) < 1:
            # Dumb symbol lookup unhelpful - aborting
            fail("No ioctl found in {0}".format(module))
            exit(0)

    newline()
    for index, (ioctl, addr) in enumerate(ioctls.iteritems(), 1):

        infos("Analyzing function {0} at {1}".format(green(ioctl), hex(addr - idaoff)))

        # Create control flow graph starting at the beginning of the ioctl
        # and get function
        cfg = project.analyses.CFGAccurate(starts=[addr])
        debug("CFG created")

        # Get function
        f = cfg.functions[addr]

        # Sometimes disassembly is incomplete. Let's try to recover the rest...
        debug("Recovering missing function blocks if necessary")
        recover_function(f, cfg, addr)

        # Manually recover 'ret' exact addresses from endpoint blocks
        ret_addr = []
        for x in f.blocks:
            present = [e.addr in x.instruction_addrs for e in f.endpoints]

            if not True in present:
                continue

            ret_addr += [i.address for i in x.capstone.insns if 'ret' in i.mnemonic]

        endpoints = list(set(ret_addr))

        if len(endpoints) < 1:
            # Trying with every block
            for x in f.blocks:
                ret_addr += [i.address for i in x.capstone.insns if 'ret' in i.mnemonic]
            endpoints = list(set(ret_addr))

        if len(endpoints) < 1:
            fail("No endpoint found for {0} - Skipping".format(ioctl))
            newline()
            continue

        debug("Endpoints: {0}".format([hex(x - idaoff) for x in endpoints]))

        # Creating blank state starting at the first instruction's address
        init = project.factory.blank_state(addr=addr)
        path_gp = project.factory.path_group(init)

        infos("Launching path_group explorer")

        simplified_equ = []
        negative_vals = []
        try:
            ex = path_gp.explore(find=endpoints)
        except Exception as e:
            smth_went_wrong('path_groups.explore', e, Constants.CRITICAL)

        while len(ex.found) or len(ex.deadended):
            infos("Explorer: {0}".format(ex))
            if len(ex.found):
                pos, neg = analyze_paths('found', ex.found, addr)
                if pos:
                    simplified_equ += pos
                if neg:
                    negative_vals += neg

            # Deadended path may be interesting, so let's check before dropping
            # them
            if len(ex.deadended):
                pos, neg = analyze_paths('deadended', ex.deadended, addr)
                if pos:
                    simplified_equ += pos
                if neg:
                    negative_vals += neg

            # We discard the found and deadended path, and we relaunch the
            # explorer until there is not found or deadended path anymore
            try:
                ex = ex.drop(stash='found')
                ex = ex.drop(stash='deadended')
                ex = path_gp.explore(find=endpoints)
            except Exception as e:
                smth_went_wrong('path_groups.explore', e, Constants.FAIL)

        # Analysis is over - Print and save values found
        if len(simplified_equ) > 0:
            success("Recovered values:")

            for eq in simplified_equ:
                infos("{0}: [{1}, {2}]".format(eq[0], hex(eq[1]), hex(eq[2])))
        infos("End of analysis")

        if config['log']:
            log(simplified_equ, negative_vals, module, ioctl)



