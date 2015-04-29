

from DIE.Lib.DataPluginBase import DataPluginBase
import idc
import idaapi

class BoolParser(DataPluginBase):
    """
    A parser for boolean values
    """

    def __init__(self):
        super(BoolParser, self).__init__()

        self.setPluginType("Bool")

    def registerSupportedTypes(self):
        """
        Register string types
        @return:
        """
        self.addSuportedType("BOOL", 0)

    def guessValues(self, rawValue):
        """
        Guess string values
        """
        if rawValue == 1:   # Guess True
            self.addParsedvalue("True", 5, "Boolean", hex(rawValue))
            return True

        if rawValue == 0:   # Guess False
            self.addParsedvalue("False", 5, "Boolean", hex(rawValue))
            return True

        return False

    def matchType(self, type):
        """
        Check if given type is of a string type
        @param type: IDA type_info_t object
        @return: True if given type is a string type otherwise False
        """
        return self.checkSupportedType(type)

    def parseValue(self, rawValue):
        """
        Parse the string value
        @return:
        """
        if rawValue == 1:   # Guess True
            self.addParsedvalue("True", 0, "Boolean", hex(rawValue))
            return True

        if rawValue == 0:   # Guess False
            self.addParsedvalue("False", 0, "Boolean", hex(rawValue))
            return True

        return False









