from awesome.context import ignored
import sark

__author__ = 'yanivb'

from idaapi import *
from idc import *
import idc
import idaapi
import idautils
import re
import os

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
        function_name = idc.Demangle(idc.GetFunctionName(ea), idc.GetLongPrm(idc.INF_SHORT_DN))

        if function_name:
            function_name = function_name.split("(")[0]

        # Function name is not mangled
        if not function_name:
            function_name = idc.GetFunctionName(ea)

        if not function_name:
            function_name = idc.Name(ea)

        # If we still have no function name, make one up. Format is - 'UNKN_FNC_4120000'
        if not function_name:
            function_name = "UNKN_FNC_%s" % hex(ea)

        return function_name

def get_function_start_address(ea):
    """
    Get function start address
    @param ea: ea from within the function boundaries.
    @return: The function start ea. If function start was not found return current ea.
    """
    try:
        if ea is None:
            return None

        start_adrs = idc.GetFunctionAttr(ea, idc.FUNCATTR_START)
        if start_adrs != idc.BADADDR:
            return start_adrs

        return ea

    except Exception as ex:
        raise RuntimeError("Count not locate start address for function %s: %s" % (hex(ea), ex))

def get_function_end_address(ea):
    """
    Get function end address
    @param ea: function start_ea.
    @return: The function end ea. If no ea found returns None.
    """
    try:
        if ea is None:
            return None

        end_adrs = idc.PrevHead( idc.GetFunctionAttr(ea, idc.FUNCATTR_END), ea)
        if end_adrs != idc.BADADDR:
            return end_adrs

        return None

    except Exception as ex:
        raise RuntimeError("Count not locate end address for function %s: %s" % (hex(ea), ex))

def get_functions():
    """
    Get all current functions
    @return: a tuple of (function_name, function_ea)
    """
    return {get_function_name(func_ea): func_ea for func_ea in idautils.Functions()}


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
    return sark.Line(ea).insn.is_call

# TODO: Change this to be architecture independent
def is_ret(ea):
    """
    Check if the current instruction a RET instruction
    """
    return sark.Line(ea).insn.is_ret

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

def is_indirect(ea):
    """
    Check if a call instruction is direct or indirect.
    @param ea: Effective address of the call instruction.
    @return:
    """
    operand = sark.Line(ea).insn.operands[0]
    # If the CALL instruction first operand is either of [Base + Index] or [Base + Index + Displacement] type.
    if operand.type.is_phrase or operand.type.is_displ:
        return True

    return False


def is_ida_debugger_present():
    """
    Check if IDA debugger is loaded and can be used
    @return: True if IDA debugger has been set correctly, Otherwise returns Fals
    """
    return idaapi.dbg_can_query()
