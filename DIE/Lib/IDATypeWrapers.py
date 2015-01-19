__author__ = 'yanivb'

import idaapi
import logging
from DIE.Lib.IDAConnector import get_native_size, regOffsetToName,\
    get_function_name, get_func_start_adr, get_function_end_adr

#
# This file contains several wrappers for common IDA data type such as Functions, Function Argument,
# Structs, Struct Elements and arrays.
# Since retrieving this type information is not such a "trivial" task in IDA API, this wrappers are
# designed to act as convenience classes, making the data more easily accessible.
#


#######################################################################################################################
#
#  IDA Array class wrapper
#

class Array():
    """
    Array Class
    """

    def __init__(self, type):

        self.logger = logging.getLogger(__name__)

        self.type_info = type
        self.array_type_data = idaapi.array_type_data_t()

        self.element_type = None
        self.element_num = 0
        self.element_size = 0

        self.elements = []

        # Extract array data
        self.get_array_data()

    def get_array_data(self):
        """
        Extract the array data from tinfo_t object and populate all relevant class properties.
        @return: True if successful, otherwise False
        """

        try:
            if self.type_info.is_array():
                if self.type_info.get_array_details(self.array_type_data):
                    self.element_type = self.array_type_data.elem_type
                    self.element_num = self.array_type_data.nelems
                    self.element_size = self.element_type.get_size()
                    return True

            return False

        except Exception as ex:
            self.logger.error("Error while getting array data: %s", ex)
            return False

#######################################################################################################################
#
#  IDA Function Argument class wrapper
#

class FuncArg():
    """
    Function argument class
    """
    def __init__(self, argType, argLoc, argNum, argName=None, isGuessed=False):
        """
        Ctor
        """
        self.logger = logging.getLogger(__name__)

        self.isGussed = isGuessed   # Is this argument known\guessed
        self.argtype = argType      # Argument type (type_info_t object)
        self.argloc = argLoc        # argloc object
        self.argNum = argNum        # Argument number (-1 for return argument)
        self.argname = argName      # Argument name

        #self.inst_parser = InstructionParserX86()

    def isReg(self):
        """
        Is a register based argument
        """
        if self.argloc.is_reg1():
            return True
        else:
            return False

    def isStack(self):
        """
        Is a stack based argument
        """
        if self.argloc.is_stkoff():
            return True
        else:
            return False

    def name(self):
        """
        Argument name
        """
        # If argument name was explicitly provided.
        if self.argname:
            return self.argname

        # If this is a return argument.
        if self.argNum is -1:
            return "Ret_Arg"

        # Otherwise, generate name according to offset.
        #native_size = self.inst_parser.get_native_size()/8
        native_size = get_native_size()/8
        return "Arg_%s" % hex(self.argNum * native_size)

    def getRegOffset(self):
        """
        Get register offset (into ph.regnames)
        """
        if self.argloc.is_reg1():
            return self.argloc.reg1()

    def offset(self):
        """
        Stack Offset for stack args, or ph.regnames offset for register args
        """
        if self.isStack():
            return self.argloc.stkoff()

        if self.isReg():
            return self.getRegOffset()

        self.logger.error("Failed to retrieve argument offset.")
        return False

    def registerName(self):
        """
        Get register name for this arg
        """
        if self.isReg():
            return regOffsetToName(self.offset())

        return None

    def type_str(self):
        """
        A string representation of the argument type
        """
        typeStr = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, self.argtype, '', '')
        if typeStr is None:
            return None

        return typeStr

    def isRetValue(self):
        """
        Is this argument a return value?
        """
        if self.argNum is -1:
            return True
        else:
            return False

    def getArgStr(self):
        """
        Get a human readable argument description string
        """
        guessedStr = ""
        if self.isGussed:
            guessedStr = "(Guessed)"

        if self.isReg():
            return "Arg: %d, Type: %s %s, Name: %s, Register: %s" % (self.argNum,
                                                                 self.type_str(),
                                                                 guessedStr,
                                                                 self.name(),
                                                                 self.registerName())

        if self.isStack():
            return "Arg: %s, Type: %s %s, Name: %s, StackOffset: %s" % (self.argNum,
                                                                    self.type_str(),
                                                                    guessedStr,
                                                                    self.name(),
                                                                    self.offset())

        return

#######################################################################################################################
#
#  IDA Function class wrapper
#

class Function():
    """
    Function class
    """

    def __init__(self, ea, iatEA=None, library_name=None):
        """
        Ctor
        """
        self.logger = logging.getLogger(__name__)

        self.ea = ea        # Effective Address of the function
        self.iatEA = iatEA  # If imported function, the address in the IAT

        self.funcName = get_function_name(self.ea)     # Function name
        self.func_start = get_func_start_adr(self.ea)  # Function start address
        self.func_end = get_function_end_adr(self.ea)  # Function end address

        self.proto_ea = self.getFuncProtoAdr()      # Address of function prototype
        self.typeInfo = idaapi.tinfo_t()            # Function type info
        self.funcInfo = idaapi.func_type_data_t()   # Function info
        self.argNum = 0                             # Number of input arguments

        self.args = []      # Function argument list
        self.retArg = None  # Return argument

        self.library_name = library_name  # If library function, name of containing library
        self.isLibFunc = False
        if self.iatEA:
            self.isLibFunc = True  # Is this a library function

        try:
            self.getArguments()

        except RuntimeError as ex:
            self.logger.error("Failed to get function arguments for function %s: %s", self.funcName, ex)

    def getFuncProtoAdr(self):
        """
        Get the effective address of the function prototype definition.
        In some cases will not be the same as the function ea (for example in library functions case)
        """
        if self.iatEA:
            return self.iatEA

        return self.ea

    def getArguments(self):
        """
        Retrieve function arguments and populate the object`s args list.
        """
        isGuessed = False  # Is function prototype guessed

        # Get function type info
        if not idaapi.get_tinfo2(self.proto_ea, self.typeInfo):
            idaapi.guess_tinfo2(self.proto_ea, self.typeInfo)
            isGuessed = True

        if self.typeInfo.empty():
            self.logger.error("Failed to retrieve function type info for function %s at %s", self.funcName, hex(self.ea))
            raise RuntimeError()

        # Get function detail
        self.typeInfo.get_func_details(self.funcInfo)

        # TODO: This seems to be creating false positives on 0 argument functions.
        #if self.funcInfo.empty():
        #    errStr = "Failed to retrieve function info for function %s" % self.funcName
        #    raise RuntimeError(errStr)

        self.argNum = len(self.funcInfo)

        # Iterate function arguments
        for argIndex in xrange(0, self.argNum):

            argType = None  # arg_type_info_t
            argLoc = None   # argloc_info
            argName = None

            #else:  # Input Argument
            argType = self.funcInfo.at(argIndex).type
            argLoc = self.funcInfo.at(argIndex).argloc
            argName = self.funcInfo.at(argIndex).name

            curArg = FuncArg(argType, argLoc, argIndex, argName, isGuessed)
            self.args.append(curArg)

        # Set return argument
        if not self.funcInfo.rettype.empty():
            self.retArg = FuncArg(self.funcInfo.rettype,
                                  self.funcInfo.retloc,
                                  -1,
                                  "Ret_Arg",
                                  isGuessed)

    def PrintFunction(self):
        """
        Print Function Information
        """
        for arg in self.args:
            print arg.getArgStr()

#######################################################################################################################
#
#  IDA Struct Element class wrapper
#

class StructElement():
    """
    Struct Element
    """

    def __init__(self, size, offset, type, name=None, comment=None):
        """
        Struct element class
        @param size: Size of element
        @param offset: Element offset within the struct
        @param type: Element type
        @param name: Element name string
        @param comment: Element comment (Optional)
        """
        self.logger = logging.getLogger(__name__)

        self.name = name
        self.comment = comment
        self.offset = offset
        self.size = size

        self.type = type

    def get_name(self):
        """
        Get struct element`s name
        """
        if self.name is None or self.name == "":
            return "field_%d" % self.offset

        return self.name

    def type_name(self):
        """
        Get type name (int, char, LPCSTR etc.)
        """
        idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, self.type, '', '')

#######################################################################################################################
#
#  IDA Struct class wrapper
#

class Struct():
    """
    Struct class
    """

    def __init__(self, type):

        self.logger = logging.getLogger(__name__)

        self.name = ""
        self.size = 0
        self.element_num = 0
        self.is_union = False

        self.elements = []

        self.type_info = type
        self.udt_type_data = idaapi.udt_type_data_t()


        try:
            if self.getStructData():
                self.getElements()

        except:
            self.logger.error("Error while extracting struct data: %s",
                          idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, type, '', ''))
            return False


    def getStructData(self):
        """
        Extract the struct data from tinfo_t object and populate all relevant class properties.
        @return: True if successful, otherwise False
        """

        try:
            if self.type_info.is_udt():
                if self.type_info.get_udt_details(self.udt_type_data):

                    self.name = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, self.type_info, '', '')
                    self.size = self.udt_type_data.size
                    self.element_num = len(self.udt_type_data)
                    self.is_union = self.udt_type_data.is_union

                    return True

            return False

        except Exception as ex:
            self.logger.error("Error while enumerating struct: %s", ex)
            return False

    def getElements(self):
        """
        Get struct elements
        """

        for element_index in xrange(0, self.element_num):
            cur_element = self.udt_type_data[element_index]
            name = None
            comment = None

            if cur_element.name is not None:
                name = cur_element.name

            if cur_element.cmt is not None:
                comment = cur_element.cmt

            strcut_elem = StructElement(cur_element.size,
                                        cur_element.offset,
                                        cur_element.type,
                                        name,
                                        comment)

            self.elements.append(strcut_elem)
