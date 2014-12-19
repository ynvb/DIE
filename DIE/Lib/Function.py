__author__ = 'yanivb'

from DIE.Lib.FuncArg import *
import DIE.Lib.IDAConnector as IDAConnector


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

        self.funcName = IDAConnector.get_function_name(self.ea)     # Function name
        self.func_start = IDAConnector.get_func_start_adr(self.ea)  # Function start address
        self.func_end = IDAConnector.get_function_end_adr(self.ea)  # Function end address

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





































