__author__ = 'yanivb'

from idaapi import *
from idc import *
import idc
import idaapi
import idautils

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