__author__ = 'yanivb'

from DIE.Lib.InstParserUtil import *


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

        self.inst_parser = InstructionParserX86()

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
        native_size = self.inst_parser.get_native_size()/8
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
            return self.inst_parser.regOffsetToName(self.offset())

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

        return None









