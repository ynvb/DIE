__author__ = 'yanivb'

from idaapi import *
from idc import *
import idc
import idaapi
import idautils
import re

################################################################
#
# IDA Connector is a utility the wraps around IDA SDK.
# It publishes convenience functions used to query and edit data
# from IDA.
#
################################################################


#TODO: 1. Gather all main IDA interaction functions to this file
#TODO: 2. Create an abstract base class for the required functions, this might enable quick portability to other platforms.

def get_function_name(ea):
        """
        Get the real function name
        """
        # Try to demangle
        funcName = idc.Demangle(idc.GetFunctionName(ea), idc.GetLongPrm(idc.INF_SHORT_DN))
        if funcName:
            first_parens = funcName.find("(")
            if first_parens != -1:
                funcName = funcName[0:first_parens]

        # Function name is not mangled
        if not funcName:
            funcName = idc.GetFunctionName(ea)

        if funcName is None or funcName is "":
            return idc.Name(ea)

        return funcName

def get_func_start_adr(ea):
    """
    Get function start address
    @param ea: ea from within the function boundaries.
    @return: The function start ea. If no ea found returns None.
    """
    start_adrs = idc.GetFunctionAttr(ea, idc.FUNCATTR_START)
    if start_adrs != idc.BADADDR:
        return start_adrs

    return None

def get_function_end_adr(start_ea):
    """
    Get function end address
    @param ea: function start_ea.
    @return: The function end ea. If no ea found returns None.
    """
    end_adrs = idc.PrevHead( idc.GetFunctionAttr(start_ea, idc.FUNCATTR_END), start_ea)
    if end_adrs != idc.BADADDR:
        return end_adrs

    return  None

def get_functions():
    """
    Get all current functions
    @return: a tuple of (function_name, function_ea)
    """
    functions = {}
    for func_ea in idautils.Functions():
        functions[get_function_name(func_ea)] = func_ea

    return functions

def get_native_size():
    """
    Get the native OS size
    @return: 16, 32, 64 value indicating the native size or None if failed.
    """
    try:
        inf = idaapi.get_inf_structure()
        if inf.is_32bit():
            return 32
        elif inf.is_64bit():
            return 64
        else:
            # Native size is neither 32 or 64 bit. assuming 16 bit.
            return 16

    except Exception as ex:
        raise RuntimeError("Could not Could not retrieve native OS size: %s" %ex)

def get_proc_type():
    """
    Get processor type
    @return: Returns the processor type or None on failure.
    """
    try:
        inf = idaapi.get_inf_structure()
        return inf.procName()

    except Exception as ex:
        raise RuntimeError("Could not retrieve processor type: %s" %ex)

# TODO: Change this to be architecture independent
def is_call(ea):
    """
    Check if the current instruction a CALL instruction
    """
    mnem = GetMnem(ea)
    if re.match('call\s+far prt', mnem):  return None
    return re.match('call', mnem)

# TODO: Change this to be architecture independent
def is_ret(ea):
    """
    Check if the current instruction a RET instruction
    """
    mnem = GetMnem(ea)
    return re.match('ret', mnem)

# TODO: Change this to be architecture independent
def get_cur_ea():
    """
    Return the current effective address
    """
    nativeSize = get_native_size()

    if nativeSize is 16:
        return GetRegValue('IP')

    if nativeSize is 32:
        return GetRegValue('EIP')

    if nativeSize is 64:
        return GetRegValue('RIP')

# TODO: Change this to be architecture independent
def get_ret_adr():
    """
    Get the return address for the current function
    """
    nativeSize = get_native_size()

    if nativeSize is 16:
        nextInst = DbgWord(GetRegValue('SP'))  # Address of instruction following the CALL

    if nativeSize is 32:
        nextInst = DbgDword(GetRegValue('ESP'))  # Address of instruction following the CALL

    if nativeSize is 64:
        nextInst = DbgQword(GetRegValue('RSP'))  # Address of instruction following the CALL

    prev_addr, farref = idaapi.decode_preceding_insn(nextInst)  # Get previous instruction

    return prev_addr

# TODO: Change this to be architecture independent
def get_sp():
    """
    Get the current stack pointer address
    """
    return GetRegValue('ESP')

def get_adrs_mem(ea):
    """
    Get the memory at address according to native size (16, 32 or 64 bit)
    """
    # Verify EA
    if not idc.isEnabled(ea):
        return None

    nativeSize = get_native_size()

    if nativeSize is 16:
        return DbgWord(ea)

    if nativeSize is 32:
        return DbgDword(ea)

    if nativeSize is 64:
        return DbgQword(ea)

# Ask hex-rays how can this be done a bit more gracefully..
def regOffsetToName(offset):
    """
    Get register name from an offset to ph.regnames
    """
    regName = idaapi.ph_get_regnames()[offset]

    if not offset in range(0,7):
        return regName.upper()

    if get_native_size() is 16:
        return regName.upper()

    if get_native_size() is 32:
        return "E" + regName.upper()

    if get_native_size() is 64:
        return "R" + regName.upper()

    return ValueError("Failed to retrieve register name.")

def get_stack_element_size():
    """
    Get size of a stack element
    @return: size of a stack element (in bytes)
    """
    return get_native_size()/8