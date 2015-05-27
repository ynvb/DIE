from awesome import context
import time
from idc import *
from idaapi import *
#from DIE.Lib.Function import *
from DIE.Lib.IDATypeWrapers import Function
from DIE.Lib.DebugValue import *
from DIE.Lib.IDAConnector import get_function_name, is_indirect, get_function_start_address, get_function_end_address
import DIE.Lib.FunctionParsers
import DIE.Lib.DIE_Exceptions

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

    ID = 0

    def __init__(self, ea, iatEA=None, is_new_func=False, library_name=None, parent_func_context=None, calling_ea=None):
        """
        Ctor
        @param ea: Effective address of the function
        @param iatEA: Effective address of IAT element (For library functions)
        @param is_indirect: Was this function called indirectly?
        @param is_new_func: Is this function missing from initial function analysis?
        @param parent_func_context: FunctionContext object of the calling function
        @param calling_ea: The ea of the call instruction used to call this function
        """
        self.logger = logging.getLogger(__name__)
        self.config = DieConfig.get_config()

        # Get a unique function context ID
        self.id = FunctionContext.ID
        FunctionContext.ID += 1

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

        self.callingEA = calling_ea                     # The ea of the CALL instruction
        self.parent_func_context = parent_func_context  # Function context of the calling function
        self.child_func_context = []                    # Array of function contexts called bu this function

        try:
            #self.callingEA = get_ret_adr()  # The ea of the CALL instruction

            self.calling_function_name = get_function_name(self.callingEA)  # Calling function name

            ### Flags
            self.no_ret_context = True  # empty flag is dropped when first call context is retrieved.
            self.is_indirect = self.check_if_indirect()  # Flag indicating whether this function was called indirectly
            self.is_new_func = is_new_func  # Flag indicating whether this function did not exist in initial analysis
            self._empty = False

        except Exception as ex:
            logging.exception("Error while initializing function context: %s", ex)
            self._make_default_instance()

        try:
             # Get this function (The Callee)
            if self.config.function_context.new_func_analysis:
                self.function = self._getFunctionHelper(ea, iatEA, library_name=library_name)
            else:
                self.function = Function(ea, iatEA, library_name=library_name)

            # Get a function parser for this function
            # (currently only GenericFunctionParser exist, and this is used to enable future extensions)
            self.function_parser = GenericFunctionParser(self.function)

        except DIE.Lib.DIE_Exceptions.DieNoFunction:
            self.logger.info("Could not retrieve function information at address: %s", hex(ea))
            self.function = None

    @property
    def empty(self):
        """ This flag is set if function was not defined. """
        return self.function is None

    def check_if_indirect(self):
        """
        Check if this function is called indirectly
        @return: True if function was called indirectly, otherwise False
        """
        try:
            if not self.callingEA:
                self.logger.error("Error: could not locate the calling ea for function %s", self.function.funcName)
                return False

            return is_indirect(self.callingEA)

        except Exception as ex:
            self.logger.error("Failed while checking for indirect call: %s", ex)
            return False

    def get_arg_values_call(self):
        """
        Get the function argument values upon function call
        @return: True if function argument values were successfully retrieved, otherwise false.
        """
        with context.Timer() as timer:
            self.no_ret_context = False  # drop the empty flag

            # If no function arg retrieval is disabled in configuration - quit:
            if not self.config.function_context.get_func_args:
                return True

            self.callRegState = self.getRegisters()  # Get registers state
            self.callValues = self.function_parser.parse_function_args_call()  # Get function Arguments

            if self.callValues is None:
                self.logger.error("Failed parsing function arguments")
                self.no_ret_context = True
                return False

        self.total_proc_time += timer.elapsed  # Add to total elapsed time

        return True

    def get_arg_values_ret(self):
        """
        Get the function argument values upon function return
        @return: True if function argument values were successfully retrieved, otherwise false.
        """

        if self.no_ret_context:
            self.logger.error("Call values must be retrieved prior to return values.")
            return False

        # If no function arg retrieval is disabled in configuration - quit:
        if not self.config.function_context.get_func_args:
            return True

        with context.Timer() as timer:
            self.retRegState = self.getRegisters()  # Get register state
            # Get function arguments
            (self.retValues, self.retArgValue) = self.function_parser.parse_function_args_ret(self.callValues)

        self.total_proc_time += timer.elapsed  # Add to total elapsed time

        return True

    def getRegisters(self):
        """
        Get a list of registers\value tuples.
        """
        return idaapi.dbg_get_registers()

    def _getFunctionHelper(self, ea, iatEA, library_name):
        """
        An helper class for getting function data. if function is not defines, tries to define it.
        @param ea: Any address within the function boundaries
        @return: Returns a Function object.
        """
        try:
            return Function(ea, iatEA, library_name=library_name)

        except DIE.Lib.DIE_Exceptions.DieNoFunction as ex:
            self.logger.debug("Trying to define a new function at address: %s", hex(ea))
            if MakeFunction(ea, BADADDR):
                self.logger.info("New function was defined at: %s", hex(ea))

                func_start_adrs = get_function_start_address(ea)
                func_end_adrs = get_function_end_address(ea)

                self.logger.debug("Analyzing new area.")
                func_t = idaapi.get_func(ea)
                idaapi.reanalyze_function(func_t)

                self.logger.debug("Refresh debugger memory")
                invalidate_dbgmem_contents(func_start_adrs, func_end_adrs)

                return Function(ea, iatEA, library_name=library_name)
                 # If this second attempt fails again, the exception should be handled by the calling function.

    def _make_default_instance(self):
        """ Return a default (empty) instance """
        self.function = None
        self.callingEA = None
        self.calling_function_name = None
        self.no_ret_context = True
        self.is_indirect = False
        self.is_new_func = False
        self.function_parser = None