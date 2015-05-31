from DIE.Lib.DataPluginBase import DataPluginBase
import idc
import idaapi

class STDBasicString(DataPluginBase):
    """
    A parser for std::basic_string
    """

    def __init__(self):
        super(STDBasicString, self).__init__()
        self.setPluginType("std::basic_string")

    def registerSupportedTypes(self):
        """
        Register string types
        @return:
        """
        self.addSuportedType("std::basic_string", 0)

    def guessValues(self, rawValue):
        """
        Guess string values
        """
        minLength = 5
        str_value = idc.DbgDword(rawValue+4)
        if str_value is None:
            return False

        value = idc.GetString(str_value, strtype=idc.ASCSTR_C)

        if value and len(value) >= minLength:
            value, raw_value = self.normalize_raw_value(value)
            self.addParsedvalue(value, 1, "std::basic_string", raw_value)
            return True

        if not value:
            value = idc.GetString(rawValue+4, strtype=idc.ASCSTR_C)
            if value and len(value) >= minLength:
                value, raw_value = self.normalize_raw_value(value)
                self.addParsedvalue(value, 1, "std::basic_string", raw_value)
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
        str_value = idc.DbgDword(rawValue+4)
        if str_value is None:
            return False

        value = idc.GetString(str_value, strtype=idc.ASCSTR_C)

        if value:
            value, raw_value = self.normalize_raw_value(value)
            self.addParsedvalue(value, 1, "std::basic_string", raw_value)
            return True

        else:
            value = idc.GetString(rawValue+4, strtype=idc.ASCSTR_C)
            value, raw_value = self.normalize_raw_value(value)
            self.addParsedvalue(value, 1, "std::basic_string", raw_value)
            return True

        return False

    def normalize_raw_value(self, value):
        """
        Normalize value.
        @param value: value to normalize
        @return: a tuple (Nomralized_Value, Raw_value)
        """

        if value is not None:
            raw_value = "0x%s" % value.encode("hex")
            value = repr(value)
            return (value, raw_value)

        return (None, None)










