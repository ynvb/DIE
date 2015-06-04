from DIE.Lib.DataPluginBase import DataPluginBase
import idc
import idaapi

class ModuleParser(DataPluginBase):
    """
    A parser for boolean values
    """

    def __init__(self):
        super(ModuleParser, self).__init__()

        self.setPluginType("Module")

    def registerSupportedTypes(self):
        """
        Register string types
        @return:
        """
        self.addSuportedType("HMODULE", 0)

    def guessValues(self, rawValue):
        """
        Guess string values
        """
        module = idc.GetModuleName(rawValue)
        if module == 0:
            return False

        self.addParsedvalue(module, 5, "Module", hex(rawValue))
        return True

    def matchType(self, type):
        """
        Check if given type is of a string type
        @param type: IDA type_info_t object
        @return: True if given type is a string type otherwise False
        """
        return True

    def parseValue(self, rawValue):
        """
        Parse the string value
        @return:
        """
        module = idc.GetModuleName(rawValue)
        if module == 0:
            return False

        self.addParsedvalue(module, 5, "Module", hex(rawValue))
        return True










