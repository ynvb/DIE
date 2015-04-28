__author__ = 'yanivb'

import logging

from idaapi import *
from idc import *
from idautils import *
from DIE.Lib.IDAConnector import get_adrs_mem

class StaticImports():
    """
    Contains static data of the IAT
    """

    def __init__(self):
        #self.logger = logging.getLogger(__name__)

        self.iat = {}
        self.current_module = None

        self.get_iat_data()

    def imp_cb(self, ea, name, ord):
        """
        Enum import callback
        """
        if name is not None:
            name = name.lower()

        self.current_module.append((ea, name, ord))

        # (Continue enumeration)
        return True

    def get_iat_data(self):
        """
        Retrive data from IAT
        """
        imp_num = idaapi.get_import_module_qty()  # Number of imported modules

        for i in xrange(0,imp_num):
            name = idaapi.get_import_module_name(i).lower()
            if not name:
                #self.logger.error("Failed to get import module name for #%d", i)
                continue

            if not name in self.iat:
                self.iat[name]= []

            self.current_module = self.iat[name]
            idaapi.enum_import_names(i, self.imp_cb)

    def is_funcname_in_module(self, func_name, module_name):
        """
        Check if function name is part of an imported module (For example: is SetTextColor part of GDI32)
        """
        if module_name is not None:
            module_name = module_name.lower()

        if func_name is not None:
            func_name = func_name.lower()

        if module_name.lower() in self.iat:
            for ea, name, ord in self.iat[module_name.lower()]:
                if name == func_name:
                    return True

        return False

    def is_funcea_in_module(self, func_ea, module_name):
        """
        Check if function address is part of an imported module (For example: is SetTextColor part of GDI32)
        """
        if module_name.lower() in self.iat:
            for ea, name, ord in self.iat[module_name.lower()]:
                if ea == func_ea:
                    return True

        return False

    def get_func_module(self, func_ea):
        """
        Get the function module (library) name (For example: for "SetTextColor", return "GDI32")
        @param func_ea: function`s effective address
        @return: Return the containing library name or None if not a library function
        """

        for lib_name in self.iat:
            (ea, name, ord) = self.iat[lib_name]
            if ea == func_ea:
                return lib_name

        return None

    def is_module_call(self, func_name, module_name, ea=None):
        """
        Checks if a function name and\or ea is part of a loaded module
        """
        if module_name is not None:
            module_name = module_name.lower()

        if func_name is not None:
            if self.is_funcname_in_module(func_name, module_name):
                return True

        if ea is not None:
            if self.is_funcea_in_module(ea, module_name):
                return True

        return False

class DbgImports():
    """
    DbgImports contains the names, ordinals and addresses of all imported functions as allocated at runtime.
    """

    def __init__(self):
        """
        Ctor
        """
        self.logger = logging.getLogger(__name__)
        self.current_module_name = None

        # Real-Time import table
        # (Key -> Real func adrs.  Value -> (ea, name, ord)}
        self.rt_import_table = {}


    def getImportTableData(self):
        """
        Update rt_import_table with current import table data.
        """

        def imp_cb(ea, name, ord):
            """
            Import enumeration callback function. used by idaapi.enum_import_names .
            """
            tmpImports.append([self.current_module_name, ea, name, ord])
            return True

        tmpImports = []  # Contains static import table data (w\o real function addresses)
        imp_num = idaapi.get_import_module_qty()  # Number of imported modules

        for i in xrange(0, imp_num):
            self.current_module_name = idaapi.get_import_module_name(i).lower()
            idaapi.enum_import_names(i, imp_cb)

        #  Get runtime function addresses and store in self.rt_import_table
        if not idaapi.is_debugger_on():
            raise RuntimeError("Debugger is not currently active.")

        for module_name, ea, name, ord in tmpImports:
            func_real_adrs = get_adrs_mem(ea)
            self.rt_import_table[func_real_adrs] = (module_name, ea, name, ord)

    def find_func_iat_adrs(self, ea):
        """
        Find the function location in the IAT table based on its runtime address
        @param ea: effective address of the function
        @return: a tuple of ('EA at the IAT' , 'Moudle Name')
        """
        if ea in self.rt_import_table:
            (module_name, iat_ea, name, ord) = self.rt_import_table[ea]
            return iat_ea, module_name

        return None, None

    def is_func_imported(self, ea):
        """
        Checks the given ea and returns True if the function is an imported function (loacted in IAT)
        """
        if ea in self.rt_import_table:
            return True

        return False

    def is_func_module(self, ea, mod_name):
        """
        Check if function at ea is part of the imported module
        """
        if ea in self.rt_import_table:
            (module, ea, name, ord) = self.rt_import_table[ea]
            if module == mod_name:
                return True

        return False

    def print_debug_imports(self):
        """
        Print the debug imports
        """
        for dbgImp in self.rt_import_table:
            (module_name, ea, name, ord) = self.rt_import_table[dbgImp]
            print "ModuleName - %s,\t\tFunctionName - %s,\t\t Address in IAT - %s,\t\t Real address - %s" % (module_name, name, hex(ea), hex(dbgImp))