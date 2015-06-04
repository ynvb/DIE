from DIE.Lib.DataPluginBase import DataPluginBase
import idc
import idaapi

class FunctionParser(DataPluginBase):
    """
    A parser for boolean values
    """

    def __init__(self):
        super(FunctionParser, self).__init__()

        self.setPluginType("Function")

    # def registerSupportedTypes(self):
    #     """
    #     Register string types
    #     @return:
    #     """
    #     self.addSuportedType("Function", 0)

    def guessValues(self, rawValue):
        """
        Guess string values
        """
        func = idaapi.get_func(rawValue)
        if func is None:
            return False

        if func.startEA == rawValue:
            func_name = idc.GetFunctionName(rawValue)
            self.addParsedvalue(func_name, 5, "Function", hex(rawValue))
            return True

        return False

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
        func = idaapi.get_func(rawValue)
        if func is None:
            return False

        if func.startEA == rawValue:
            func_name = idc.GetFunctionName(rawValue)
            self.addParsedvalue(func_name, 5, "Function", hex(rawValue))
            return True

        return False









