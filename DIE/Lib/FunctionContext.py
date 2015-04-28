__author__ = 'yanivb'

import time

from idc import *
from idaapi import *
#from DIE.Lib.Function import *
from DIE.Lib.IDATypeWrapers import Function
from DIE.Lib.DebugValue import *
from DIE.Lib.IDAConnector import get_function_name, get_ret_adr, is_indirect
import DIE.Lib.FunctionParsers

from DIE.Lib.FunctionParsers.GenFuncParser import GenericFunctionParser


class FunctionContext():
    """
    Function context stores all runtime context of a given function call.
    A single function may be assigned to multiple FunctionContext objects, because a unique function context will
    be created every time this function is called.
    The information stored is the value of the function arguments and registers at function call
    and function return.
    It also holds various other useful information regarding this specific function call such as:
     1. "was this function called indirectly"
     2. "did this function exist in the original analysis"
     3. "who called this function"
     4. "how much time did it take to process this function"
    """

    def __init__(self, ea, iatEA=None, is_new_func=False, library_name=None):
        """
        Ctor
        @param ea: Effective address of the function
        @param iatEA: Effective address of IAT element (For library functions)
        @param is_indirect: Was this function called indirectly?
        @param is_new_func: Is this function missing from initial function analysis?
        """
        self.logger = logging.getLogger(__name__)
        self.config = DieConfig.get_config()

        ################################################################################
        ### Context Stuff

        # Arguments
        self.callValues = []        # Argument values at function call
        self.retValues = []         # Argument values at function return
        self.retArgValue = None     # Return argument value

        # Registers
        self.callRegState = None    # Register state at function call
        self.retRegState = None     # Register state at function return
        self.total_proc_time = 0    # Total processing time in seconds.

        try:
            ### Function Data
            self.function = Function(ea, iatEA, library_name=library_name)  # This (The Callee) function
            self.callingEA = get_ret_adr()  # The ea of the CALL instruction
            self.calling_function_name = get_function_name(self.callingEA)  # Calling function name

            ### Flags
            self.empty = True  # empty flag is dropped when first call context is retrieved.
            self.is_indirect = self.check_if_indirect()  # Flag indicating whether this function was called indirectly
            self.is_new_func = is_new_func  # Flag indicating whether this function did not exist in initial analysis

            # TODO: if this is a new function, try to define it.

            # Get a function parser for this function
            # (currently only GenericFunctionParser exist, and this is used to enable future extensions)
            self.function_parser = GenericFunctionParser(self.function)

        except Exception as ex:
            logging.exception("Error while initializing function context: %s", ex)
            return None

    def check_if_indirect(self):
        """
        Check if this function is called indirectly
        @return: True if function was called indirectly, otherwise False
        """
        if not self.callingEA:
            self.logger.error("Error: could not locate the calling ea for function %s", self.function.funcName)
            return False

        return is_indirect(self.callingEA)

    def get_arg_values_call(self):
        """
        Get the function argument values upon function call
        @return: True if function argument values were successfully retrieved, otherwise false.
        """
        try:
            start_time = time.time()  # Start timer
            self.empty = False  # drop the empty flag

            # If no function arg retrieval is disabled in configuration - quit:
            if not self.config.get_func_args:
                return True

            self.callRegState = self.getRegisters()  # Get registers state
            self.callValues = self.function_parser.parse_function_args_call()  # Get function Arguments

            if self.callValues is None:
                self.logger.error("Failed parsing function arguments")
                self.empty = True
                return False

            elapsed_time = time.time() - start_time  # Get elapsed time
            self.total_proc_time += elapsed_time  # Add to total elapsed time

            return True

        except Exception as ex:
            self.logger.exception("Failed to get argument call value: %s", ex)

    def get_arg_values_ret(self):
        """
        Get the function argument values upon function return
        @return: True if function argument values were successfully retrieved, otherwise false.
        """
        try:
            if self.empty:
                self.logger.error("Call values must be retrieved prior to return values.")
                return False

            # If no function arg retrieval is disabled in configuration - quit:
            if not self.config.get_func_args:
                return True

            start_time = time.time()  # Start timer

            self.retRegState = self.getRegisters()  # Get register state
            # Get function arguments
            (self.retValues, self.retArgValue) = self.function_parser.parse_function_args_ret(self.callValues)

            elapsed_time = time.time() - start_time  # Get elapsed time
            self.total_proc_time += elapsed_time  # Add to total elapsed time

            return True

        except Exception as ex:
            self.logger.exception("Failed to get argument return value: %s", ex)

    def getRegisters(self):
        """
        Get a list of registers\value tuples.
        """
        return idaapi.dbg_get_registers()





