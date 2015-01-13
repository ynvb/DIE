__author__ = 'yanivb'

import time

from idc import *
from idaapi import *
from DIE.Lib.Function import *
from DIE.Lib.DebugValue import *
from DIE.Lib.InstParserUtil import *
import DIE.Lib.IDAConnector
import DIE.Lib.FunctionParsers


class FunctionContext():
    """
    Function context stores the runtime context of a given function.
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

        self.instParser = InstructionParserX86()

        ################################################################################
        ### Context Stuff

        # Arguments
        self.callValues = []                            # Argument values at function call
        self.retValues = []                             # Argument values at function return
        self.retArgValue = None                         # Return argument value

        # Registers
        self.callRegState = None                        # Register state at function call
        self.retRegState = None                         # Register state at function return
        self.total_proc_time = 0                        # Total processing time in seconds.

        try:
            self.function = Function(ea, iatEA, library_name=library_name)  # This (The Callee) function
            self.callingEA = self.instParser.get_ret_adr()                  # The ea of the CALL instruction
            self.calling_function_name = DIE.Lib.IDAConnector.get_function_name(self.callingEA)  # Calling function name

        ###############################################################################
        ### Flags

            self.empty = True  # empty flag is dropped when first call context is retrieved.
            self.is_indirect = self.check_if_indirect()  # Flag indicating whether this function was called indirectly
            self.is_new_func = is_new_func  # Flag indicating whether this function did not exist in initial analysis

            # TODO: if this is a new function, try to define it.

            # Get an argument parser for this function.
            function_parsers = DIE.Lib.FunctionParsers.get_function_parsers()
            self.argument_parser = function_parsers.get_arg_parser(self.function.funcName, self.callingEA)

        except Exception as ex:
            logging.critical("Error while initializing function context: %s", ex)
            return False

    def check_if_indirect(self):
        """
        Check if this function is called indirectly
        @return: True if function was called indirectly, otherwise False
        """
        if not self.callingEA:
            self.logger.error("Error: could not locate the calling ea for function %s", self.function.funcName)
            return False

        op_type = idc.GetOpType(self.callingEA, 0)

        # If the CALL instruction first operand is either a Register, or of [Base + Index] type.
        if op_type == 1 or op_type == 3 or op_type == 4:
            self.logger.debug("Indirect call found. function - %s, ea - %s", self.function.funcName, hex(self.callingEA))
            return True

        return False

    def get_arg_value(self, argument):
        """
        Get an argument runtime value
        @param argument: The argument which runtime value to retrieve
        @return: DebugValue object containing the current argument value. Returns None on failure
        """
        try:
            storeType = None
            argtype = None
            loc = None

            # If register based argument
            if argument.isReg():
                storeType = REG_VAL
                loc = argument.registerName()

            # If stack based argument
            if argument.isStack():
                storeType = MEM_VAL
                retAdrSize = self.instParser.get_native_size()/8  # Size of stack return address
                loc = self.instParser.get_sp() + retAdrSize + argument.offset()  # Absolute arg stack address

            if not argument.isGussed:
                argtype = argument.argtype

            argValue = self.argument_parser.get_arg_value(argument.argNum,  # Argument Index
                                                          storeType,        # Register \ Stack
                                                          loc,              # Value location
                                                          argtype,          # Argument type
                                                          argument.name(),  # Argument name
                                                          1)                # return=0\call=1

            return argValue

        except Exception as ex:
           self.logger.error("Error: Could not retrieve argument call value: %s", ex)
           return None

    def get_arg_values_call(self):
        """
        Get the call values at the current location.
        """
        start_time = time.time()  # Start timer

        self.empty = False  # drop the empty flag

        # If no function arg retrieval is disabled in configuration - quit:
        if not self.config.get_func_args:
            return True

        self.callRegState = self.getRegisters()  # Get register state

        argIndex = 0
        for arg in self.function.args:
            arg_value = self.get_arg_value(arg)
            self.callValues.append(arg_value)
            argIndex += 1

        elapsed_time = time.time() - start_time  # Get elapsed time
        self.total_proc_time += elapsed_time  # Add to total elapsed time

        return True

    def get_arg_values_ret(self):
        """
        Get the argument values at the current location
        (This function is meant to be called when current position is at the function return instruction)
        """
        start_time = time.time()  # Start timer

        if self.empty:
            self.logger.error("Call values must be retrieved prior to return values.")
            return False

        # If no function arg retrieval is disabled in configuration - quit:
        if not self.config.get_func_args:
            return True

        self.retRegState = self.getRegisters()  # Get register state

        # Iterate trough call values, and update current values.
        argIndex = 0
        for call_value in self.callValues:
            retValue = self.argument_parser.get_arg_value(argIndex,              # Argument Index
                                                          call_value.storetype,  # Register \ Stack
                                                          call_value.loc,        # Value location
                                                          call_value.type,       # Argument type
                                                          call_value.name,       # Argument name
                                                          0)                     # return=0\call=1

            #retValue = DebugValue(call_value.storetype, call_value.loc, call_value.type, call_value.name)
            self.retValues.append(retValue)
            argIndex += 1

        # Get return argument value
        if self.function.retArg:
            self.retArgValue = self.get_arg_value(self.function.retArg)

        elapsed_time = time.time() - start_time  # Get elapsed time
        self.total_proc_time += elapsed_time  # Add to total elapsed time

        return True

    def getRegisters(self):
        """
        Get a list of registers\value tuples.
        """
        return idaapi.dbg_get_registers()

    def get_context(self):
        """
        Get the stored function context.
        @return: a tuple containing 3 list of DebugValue objects.
        (CallArgValues, RetArgValues, RetArgument)

            CallArgValues - Argument values at function call
            RetArgValues  - Argument values at function return
            RetArgument    - Return argument(s) value
        """

        return (self.callValues, self.retValues, self.retArgValue)





