__author__ = 'yanivb'
import logging
import pickle
import os

import idaapi
import idc
import idautils

from DIE.Lib.DbgImports import StaticImports
from DIE.Lib.IDAConnector import *
import DIE.Lib.DIEDb


# Was user breakpoint flag definition
WAS_USER_BREAKPOINT = 0x1

# Match type definition. used for partial function name matching.
STARTS_WITH = 0
ENDS_WITH = 1
CONTAINS = 2

class BpHandler():
    """
    Main breakpoint handling class.
    Used to control all breakpoint related operations, such as dynamic\static breakpoints setting,
    breakpoint exceptions and serialization.
    """

    def __init__(self):

        self.logger = logging.getLogger(__name__)

        self.iat = StaticImports()              # Static IAT
        self.die_db = DIE.Lib.DIEDb.get_db()    # DIE DB

        # Walked function list is used with dynamic (runtime) breakpointing
        # it keeps track of previously walked functions in order to avoid walking them again.
        self.walked_functions = {}

    ###############################################################################################
    #   Public properties

    @property
    def bp_list(self):
        return self.die_db.bp_list

    @property
    def excluded_modules(self):
        return self.die_db.excluded_modules

    @property
    def excluded_funcNames(self):
        return self.die_db.excluded_funcNames

    @property
    def excluded_bp_ea(self):
        return self.die_db.excluded_bp_ea

    @property
    def excluded_funcNames_part(self):
        return self.die_db.excluded_funcNames_part

    ###############################################################################################
    #   Breakpoint handling functions

    def setBPs(self):
        """
        Set breakpoints on all CALL and RET instructions in all of the executable sections.
        """
        for seg_ea in idautils.Segments():
            for head in idautils.Heads(seg_ea, idc.SegEnd(seg_ea)):
                if idc.isCode(idc.GetFlags(head)):
                    # Add BP if instruction is a CALL
                    if is_call(head):
                        self.addBP(head)

    def unsetBPs(self):
        """
        Remove all DIE set BreakPoints
        @return: Returns True if successful, otherwise return False
        """
        try:
            for ea in self.die_db.bp_list:
                (bp_flags, bp_desc) = self.die_db.bp_list[ea]
                if bp_flags & WAS_USER_BREAKPOINT:
                    return

                idc.DelBpt(ea)  # Remove breakpoint

            self.die_db.bp_list.clear()  # Clear the breakpoint list.

            # Clear walked function list if necessary.
            if self.walked_functions is not None:
                self.walked_functions.clear()

        except Exception as ex:
            self.logger.error("Failed to remove breakpoints: %s", ex)

    def addBP(self, ea, bp_description=None):
        """
        Add a breakpoint
        @param ea: The location address to add the breakpoint
        @param bp_description: A breakpoint description
        @return: True if breakpoint was added, otherwise False. Returns -1 if an error occurred.
        """
        try:
            if idc.CheckBpt(ea) > 0:
                # If our breakpoint already exist
                if ea in self.die_db.bp_list:
                    return False
                # Must be a user defined breakpoint then..
                self.die_db.bp_list[ea] = (WAS_USER_BREAKPOINT, bp_description)
            else:
                # Check if breakpoint is not excluded.
                if self.is_exception_call(ea):
                    return False
                self.die_db.bp_list[ea] = (0, bp_description)
                idc.AddBpt(ea)

            return True

        except Exception as ex:
            self.logger.error("Could not add breakpoint: %s", ex)
            return -1

    def removeBP(self, ea):
        """
        Remove a breakpoint
        @param ea:
        @return: True if breakpoint was removed, otherwise False. Returns -1 if an error occurred.
        """
        try:
            if not ea in self.die_db.bp_list:
                return False

            (bp_flags, bp_desc) = self.die_db.bp_list[ea]
            if bp_flags & WAS_USER_BREAKPOINT:
                return True

            idc.DelBpt(ea)           # Remove breakpoint
            self.die_db.bp_list.pop(ea)     # Remove from breakpoint list

            return True

        except Exception as ex:
            self.logger.error("Could not remove breakpoint: %s", ex)
            return -1

    ###############################################################################################
    #   Breakpoint exception handling functions

    def is_exception_call(self, ea):
        """
        Main exception checking function.
        Checks if the requested call instruction ea is part of exception list.
        @param ea: The address to check
        @return: True if the given address is to be excepted from breakpoint list, otherwise False
        """
        try:
            # Check if in excluded breakpoint addresses list
            if ea in self.die_db.excluded_bp_ea:
                return True

            # Try to extract function name. if extraction failed no further checks can be made.
            func_ea, func_name = self.get_called_func_data(ea)
            if func_name is None and func_ea is None:
                return False

            # Check if called function name is part of an excluded module
            for module_name in self.die_db.excluded_modules:
                if self.iat.is_module_call(func_name, module_name, func_ea):
                    return True

            # Next checks check for function name matching. they are irrelevant if no function name is available.
            if func_name is None:
                return False

            # Check if called function name is in excluded function name list.
            if func_name in self.die_db.excluded_funcNames:
                return True

            for func_part, match_type in self.die_db.excluded_funcNames_part:

                if match_type == STARTS_WITH:
                    if func_name.startswith(func_part):
                        return True

                if match_type == ENDS_WITH:
                    if func_name.endswith(func_part):
                        return True

                if match_type == CONTAINS:
                    if func_name.find(func_part) != -1:
                        return True

            # Feeeew, Nothing matched..
            return False

        except Exception as ex:
            self.logger.error("Failed to check for breakpoint exception: %s", ex)
            return False

    def is_exception_func(self, ea, iatEA):
        """
        Check if the address is part of an excluded function.
        @param ea: An address from within the function boundaries
        @param iatEA: An address of the function in the IAT
        @return: True if the given address is excepted from breakpoint list, otherwise False
        """
        try:
            func_adr = ea

            if iatEA is not None:
                func_adr = iatEA

            func_name = get_function_name(func_adr)

            if func_name in self.die_db.excluded_funcNames:
                return True

            return False

        except Exception as ex:
            self.logger("Failed checking if function at address %s is excepted: %s", hex(ea), ex)
            return False

    def reload_bps(self):
        """
        Reload current breakpoints according to current exception lists
        @return: True if bps were reloaded sucessfully, otherwise False.
        """
        try:
            self.logger.debug("Reloading breakpoint exceptions")
            for bp_ea in self.die_db.bp_list.keys():
                if self.is_exception_call(bp_ea):
                    if self.removeBP(bp_ea):
                        self.logger.debug("breakpoint exception removed from %s", hex(bp_ea))

            self.logger.debug("Breakpoints were reloaded successfully")
            return True

        except Exception as ex:
            self.logger.error("Failed while reloading exceptions: %s", ex)
            return False

    def add_module_exception(self, module_name, reload_bps=False):
        """
        Add a loaded module name (i.e "user32") to be excepted.
        no breakpoints will be set on functions contained in this module.
        @param module_name: The excepted module
        @param reload_bps: reload breakpoints
        @return: True if added successfully, otherwise False
        """
        try:
            if module_name is None:
                return False

            module_name = module_name.lower()

            if module_name in self.die_db.excluded_modules:
                self.logger.debug("Cannot add module %s to excluded module list. module already exist", module_name)
                return True

            self.logger.info("Module %s added to exception list.", module_name)
            self.die_db.excluded_modules.append(module_name)

            if reload_bps:
                self.reload_bps()

            return True

        except Exception as ex:
            self.logger.error("Could not add module \"%s\" to excluded module list:", module_name, ex)
            return False

    def add_bp_ea_exception(self, ea, reload_bps=False):
        """
        Add excluded address. no breakpoints will be set on this address.
        @param ea: Address to be excluded
        @param reload_bps: reload breakpoints
        @return: True if added successfully, otherwise False
        """
        try:
            if ea is None:
                return False

            if ea in self.die_db.excluded_bp_ea:
                self.logger.debug("Cannot add address %s to excluded address list. address already exist", hex(ea))
                return True

            self.logger.info("Address %s added to exception list", hex(ea))
            self.die_db.excluded_bp_ea.append(ea)

            if reload_bps:
                self.reload_bps()

        except Exception as ex:
            self.logger.error("Could not add address %s to excluded address list: %s", hex(ea), ex)
            return False

    def add_bp_funcname_exception(self, funcName, reload_bps=False):
        """
        Add excluded function name. no breakpoint will be set on CALL statements to this function.
        Note: at some cases (like indirect calls) call destination is unknown prior to runtime and cannot be excluded.
        @param funcName: Function name to be excluded
        @param reload_bps: reload breakpoints
        @return: True if added successfully, otherwise False
        """
        try:
            if funcName is None:
                return False

            funcName = funcName.lower()

            if funcName in self.die_db.excluded_funcNames:
                self.logger.debug("Cannot add function name %s to excluded function name list. "
                                 "function name already exist", funcName)
                return True

            self.logger.info("Function name \"%s\" was added to exception list", funcName)
            self.die_db.excluded_funcNames.append(funcName)

            if reload_bps:
                self.reload_bps()

        except Exception as ex:
            self.logger.error("Could not add function name %s to excluded function names list:", funcName, ex)
            return False

    def add_bp_funcname_part_exception(self, func_name_part, match_type=STARTS_WITH, reload_bps=False):
        """
        Add excluded function partial name. no breakpoint will be set on CALL statements to function that match.
        @param func_name_part: partial function name to match
        @param match_type: type of matching to preform on partial name. possible values are:
                    STARTS_WITH = 0 (Default)
                    ENDS_WITH = 1
                    CONTAINS = 2
        @param reload_bps: reload breakpoints
        @return: True if added successfully, otherwise False
        """
        try:
            if func_name_part is None:
                return False

            func_name_part = func_name_part.lower()

            match_tup = (func_name_part, match_type)

            if match_tup in self.die_db.excluded_funcNames_part:
                self.logger.debug("Cannot add partial function name %s to excluded partial function name list. "
                "function name already exist", func_name_part)

                return True

            if match_type == STARTS_WITH:
                self.logger.info("Function names that start with \"%s\" were added to exception list", func_name_part)
            if match_type == ENDS_WITH:
                self.logger.info("Function names that end with \"%s\" were added to exception list", func_name_part)
            if match_type == CONTAINS:
                self.logger.info("Function names that contain \"%s\" were added to exception list", func_name_part)

            self.die_db.excluded_funcNames_part.append(match_tup)

            if reload_bps:
                self.reload_bps()

        except Exception as ex:
            self.logger.error("Could not add partial function name %s "
                              "to excluded partial function names list: %s", func_name_part, ex)
            return False

    def get_called_func_data(self, ea):
        """
        Try to get the called function name and address.
        @param ea: Address to the CALL instruction
        @return: On success a tuple of called function data (Function_ea, Demangled_Function_Name).
        otherwise (None,None) tuple will be returned
        """
        try:
            func_name = None
            call_dest = None

            if idc.isCode(idc.GetFlags(ea)):
                if is_call(ea):
                    operand_type = idc.GetOpType(ea, 0)
                    if operand_type == 5 or operand_type == 6 or operand_type == 7 or operand_type == 2:
                        call_dest = idc.GetOperandValue(ea, 0)  # Call destination
                        func_name = get_function_name(call_dest).lower()

            return call_dest, func_name

        except Exception as ex:
            self.logger.error("Failed to get called function data: %s", ex)
            return None, None

    ###############################################################################################
    #   Dynamic (RunTime) Breakpoints

    def walk_function(self, ea):
        """
        Walk function and place breakpoints on every call function found within it.
        @param ea: An effective address within the function.
        @return: True if function walked succeeded or False otherwise
        """
        try:
            function_name = get_function_name(ea)
            if function_name in self.walked_functions:
                self.logger.debug("No breakpoints will be set in function %s, "
                                  "since it was already walked before.", function_name)
                return True

            # Add function to walked function list
            self.walked_functions[function_name] = ea

            start_adrs = get_func_start_adr(ea)
            end_adrs = get_function_end_adr(ea)

            # Walk function and place breakpoints on every call instruction found.
            for head in idautils.Heads(start_adrs, end_adrs):
                if idc.isCode(idc.GetFlags(head)):
                    # Add BP if instruction is a CALL
                    if is_call(head):
                        self.addBP(head)

                # If current ea is not code, quit.
                else:
                    break

            self.logger.debug("Function %s was successfully walked for breakpoints", function_name)
            return True

        except Exception as ex:
            self.logger.error("Failed walking function at address %s for breakpoints.", hex(ea))
            return False

    def flush_walked_funcs(self):
        """
        Erase all previously walked function history
        @return: True on success, otherwise False
        """
        self.walked_functions.clear()
        return True

    ###############################################################################################
    #   Load\Save Exceptions to DIE DB

    def load_exceptions(self, die_db):
        """
        Load exceptions from db
        @return:
        """
        try:
            if not isinstance(die_db, DIE.Lib.DIEDb.DIE_DB):
                self.logger.error("Wrong type. expected DIE_DB.")
                return False

            self.die_db.excluded_bp_ea = die_db.excluded_bp_ea
            self.die_db.excluded_funcNames = die_db.excluded_funcNames
            self.die_db.excluded_modules = die_db.excluded_modules
            self.die_db.excluded_funcNames_part = die_db.excluded_funcNames_part

            return True

        except Exception as ex:
            logging.error("Failed while loading breakpoint exception data from db: %s", ex)
            return False

    def save_exceptions(self, die_db):
        """
        Save exceptions to db
        @return:
        """
        try:
            if not isinstance(die_db, DIE.Lib.DIEDb.DIE_DB):
                self.logger.error("Wrong type. expected DIE_DB.")
                return False

            die_db.excluded_bp_ea = self.die_db.excluded_bp_ea
            die_db.excluded_funcNames = self.die_db.excluded_funcNames
            die_db.excluded_modules = self.die_db.excluded_modules
            die_db.excluded_funcNames_part = self.die_db.excluded_funcNames_part

            return True

        except Exception as ex:
            logging.error("Failed while saving exception data to db: %s", ex)
            return False


################# [ Singleton ] ######################
_bp_handler = BpHandler()

def get_bp_handler():
    if _bp_handler is not None:
        return _bp_handler
