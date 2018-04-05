from constants import *
from utils import *

def hook_me_maybe(state):
    state.regs.rax = 0


def get_registering_function(project):
    """
    IOCTLs are registered using known and specific functions. This function
    tries to find which one is used.

    :return: The function's rebased address
    """
    # Get registering_functions from imports
    elf = project.loader.all_elf_objects[0]
    found = [x for x in elf.imports if x in Constants.register_functions]
    found = list(set(found))

    if len(found) > 1:
        # Multiple functions found
        smth_went_wrong('get_ioctl_from_fops', 'More than one register function found', Constants.FAIL)
        return None
    elif len(found) < 1:
        # No function found
        smth_went_wrong('get_ioctl_from_fops', 'No register function found', Constants.FAIL)
        return None

    # Remove one to get to the E8 byte
    registered_address = elf.imports[found[0]].rebased_addr - 1

    debug("Register function found: {0}".format(found[0]))

    return registered_address


def get_caller(project, r_addr, cfg):
    """
    Functions that register IOCTLs *should* be called in 'init_module'.
    EDIT: No, they are not.

    This function tries to determine which function calls the registering one.

    :return: the init_module's function
    """

    elf = project.loader.all_elf_objects[0]
    for _, sym in elf.symbols_by_addr.iteritems():
        if r_addr > sym.rebased_addr and r_addr <= sym.rebased_addr + sym.size:
            caller = sym.name

    try:
        parent = project.kb.functions[caller]
        return parent

    except:
        smth_went_wrong('get_ioctl_from_fops', 'init_module not found', Constants.FAIL)

    return None


def get_ioctl_from_fops(project):
    """
    Recover IOCTLs from fops structures

    :return: One or two addresses corresponding to unlocked and compat ioctls
             respectively
    """

    # TODO: CFGAccurate fails when CFGFast succeed, why ?
    try:
        cfg = project.analyses.CFGFast()
        #cfg = project.analyses.CFGAccurate()
    except:
        return []

    idaoff = config['ida_offset']

    call_addr = get_registering_function(project)
    if call_addr is None:
        return []

    # Offset of unlocked_ioctl in fops
    # Luckily, the offset is 64 on 64 bits machines, and 32 on 32bits machine...
    ptr_size = project.arch.bits / 8
    UNLOCKED_OFFSET = project.arch.bits
    COMPAT_OFFSET = UNLOCKED_OFFSET + ptr_size

    parent = get_caller(project, call_addr, cfg)
    if parent is None:
        return []

    # Race conditions with CFG apparently not joining his threads
    # May need to restart it...
    block_addr = None
    while block_addr is None:
        for block in parent.blocks:
            if call_addr in xrange(block.addr, block.size + block.addr):
                block_addr = block.addr
                break
        smth_went_wrong('get_ioctl_from_fops', "Incomplete CFG - Restarting analysis...", Constants.WARNING)
        cfg = project.analyses.CFG()
        parent = get_caller(project, call_addr, cfg)
        recover_function(parent, cfg, parent.addr)
    debug("Launching explorer from {0} to {1}".format(hex(block_addr), hex(call_addr)))

    # Launching path groups towards xref
    try:
        init = project.factory.blank_state(addr=block_addr)
        path_gp = project.factory.path_group(init)
        ex = path_gp.explore(find=call_addr + 5)
        debug("IOCTL explorer: {0}".format(ex))

        # Now, we pray...
        try:
            state = ex.found[0].state
        except:
            state = ex.deadended[0].state
    except Exception as e:
        smth_went_wrong('get_ioctl_from_ops', e, Constants.FAIL)
        return

    # Examining structure in memory
    # Let's try to match both seen call conventions...
    # (RCX, RDX, R8) || (RDI, RSI, RDX)
    try:
        reg = state.regs.r8.args[0]
        if reg == 0:
            raise ValueError()
    except Exception as e:
        smth_went_wrong('get_ioctl_from_fops', 'r8 fail, using rsi', Constants.WARNING)
        reg = state.regs.rsi.args[0]

    try:
        hex(reg)
        debug("fops at {0}".format(hex(reg)))
    except:
        smth_went_wrong('get_ioctl_from_fops', 'fops addr is symbolic', Constants.FAIL)
        return


    unlocked_offset = reg + UNLOCKED_OFFSET
    compat_offset = reg + COMPAT_OFFSET

    msg = "Craving ioctls at {0} and {1}"
    debug(msg.format(hex(unlocked_offset), hex(compat_offset)))

    """
    mem = state.memory.load(reg,  0x120, endness='Iend_LE')

    if not isinstance(mem.args[0], (int, long)):
        smth_went_wrong('get_ioctl_from_fops', 'Memory is symbolic - Can not get fops', Constants.CRITICAL)

    mem = mem.args[0]
    print(hex(mem))
    mem = mem / pow(pow(0x10, 0x120 - UNLOCKED_OFFSET + 4), 2)
    print(hex(mem))
    unlocked = mem & 0xffffffff
    compat = mem & 0xffffffff00000000

    print(unlocked, compat)
    print(hex(unlocked), hex(compat))

    if unlocked == 0:
        unlocked = None
    if compat == 0:
        compat = None

    msg = "Unlocked ioctl: {0} - Compat ioctl: {0}"
    success(msg.format(hex(unlocked - idaoff), hex(compat - idaoff)))

    if unlocked == compat:
    # Compat and unlocked IOCTLs are the same one, so we just return one
        return [unlocked, None]

    return [unlocked, compat]
    """

def recover_function(f, cfg, addr):
    """
    Disassembly often stops too early. Here, we will try to resolve every call
    destination in order to handle as much information as possible

    :param f:    function to recover
    :param cfg:  CFGFast
    :param addr: address of the function

    Only works with CFGFast, even if it is supposed to be broken...
    """
    calls = []
    # Get every call destination
    for blk in f.blocks:
        # Blocks are broken on calls, so we just have to check the last instruction
        last_ins = len(blk.capstone.insns) - 1
        ins = blk.capstone.insns[last_ins]
        if 'call' in ins.mnemonic:

            # Register based call should not be handled
            try:
                offset = struct.unpack("<L", ins.bytes[1:])[0]
                calls.append(offset + 5 + ins.address)

                # Yay, let's hack again. What happens when the last instruction
                # of a block is a call...? IT FAILS. Because the following
                # instruction is not registered, even if in another
                # block (the call is implicit)
                #
                # Only useful in case of hooking
                calls.append(ins.address + 5)

            except Exception as e:
                # Mostly register based calls
                smth_went_wrong('recover_function', e, Constants.DEBUG)

    # Clear doubles
    calls = list(set(calls))

    # For each previously found call, add the corresponding block to the function
    for c in calls:
        try:
            for blk in cfg.functions[c].blocks:
                if blk.addr in f._block_sizes:
                    # Block already registered - skipping
                    continue
                f._block_sizes[blk.addr] = blk.size
                recover_function(f, cfg, blk.addr)

        except Exception as e:
            smth_went_wrong('recover_function', e, Constants.DEBUG)


def get_ioctls_from_name(project, functions=None):
    """
    Returns a map of ioctls with their names and addresses

    Relies only on the fact that ioctls should be named *ioctl*

    :param function: functions to get addresses of
    :return:         Map of ioctls with their addresses
    """
    ioctls = {}
    binary = project.loader.main_bin

    # User specified functions to peel
    if functions:
        for addr, sym in binary.symbols_by_addr.iteritems():
            if sym.name in functions:
                ioctls[sym.name] = sym.rebased_addr
        return ioctls

    for addr, sym in binary.symbols_by_addr.iteritems():
        debug("Looking for ioctls: {0} ({1})".format(sym.name, hex(addr)))
        if 'ioctl' in sym.name:
            ioctls[sym.name] = sym.rebased_addr

    if len(ioctls) > 0:
        debug("Found {0} ioctls".format(len(ioctls)))

    return ioctls

def get_ioctl_from_dwarf(project):
    """
    Recovers IOCTLs from DWARFs if symbols are present

    :return:         Map of ioctls with their addresses
    """

    ioctls = {}

    # No DWARF symbols in the binary
    if not project.loader.main_bin.reader.has_dwarf_info():
        return ioctls

    infos = project.loader.main_bin.reader.get_dwarf_info()

    # file_operations offset in DWARF
    fodo = -1

    # file_operations address in data
    reloc = -1

    # ioctls offsets in fops
    compat = -1
    unlocked = -1


    # Find the DIE that contains the file_operations declaration, and get the
    # offset of its attributes (especially *ioctl)
    for cu in infos.iter_CUs():
        for die in cu.iter_DIEs():
            try:
                if 'file_operations' in die.attributes['DW_AT_name'] and die.has_children:
                    fodo = die.offset
                    for child in die.iter_children():
                        try:
                            if 'compat_ioctl' in child.attributes['DW_AT_name']:
                                compat = child.attributes['DW_AT_data_member_location'].value
                            if 'unlocked_ioctl' in child.attributes['DW_AT_name']:
                                unlocked = child.attributes['DW_AT_data_member_location'].value
                        except:
                            pass
                    break
            except:
                pass

    # Find the location of the structure in the binary
    for cu in infos.iter_CUs():
        for die in cu.iter_DIEs():
            try:
                name = die.attributes['DW_AT_name'].value
                if die.attributes['DW_AT_type'].value == fodo:
                    name = die.attributes['DW_AT_name'].value
                    reloc = die.attributes['DW_AT_location'].value
                    debug('file_operations {0} is at {1}'.format(name, reloc))
                    break
            except:
                pass

    if reloc == -1:
        smth_went_wrong('get_ioctl_from_dwarf', 'file_operations var not found', Constants.FAIL)
        return

    # TODO:
    # Find the ioctl values from the fops member by reading into memory
    # READ IN DATA SECTION THE WORD AT ADDRESS reloc + {unlocked, compat}
    try:
        unlocked = project.loader.main_bin.symbols_by_addr[unlocked]
        compat = project.loader.main_bin.symbols_by_addr[compat]
        ioctls[unlocked.name] = unlocked.rebased_addr
        ioctls[compat.name] = compat.rebased_addr
    except Exception as e:
        smth_went_wrong('get_ioctl_from_dwarf', e, Constants.FAIL)

    return ioctls
