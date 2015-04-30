

from DIE.Lib.DataPluginBase import DataPluginBase
import idc
import idaapi

# TODO: Add more string types.
ASCII_STR = 0       # ASCII String
UNICODE_STR = 1     # Unicode String

class StringParser(DataPluginBase):
    """
    A generic string value parser
    """

    def __init__(self):
        super(StringParser, self).__init__()

    def registerSupportedTypes(self):
        """
        Register string types
        @return:
        """
        self.addSuportedType("LPCSTR", ASCII_STR)
        self.addSuportedType("CHAR *", ASCII_STR)
        self.addSuportedType("CONST CHAR *", ASCII_STR)
        self.addSuportedType("LPSTR", ASCII_STR)
        self.addSuportedType("CSTRING *", ASCII_STR)
        self.addSuportedType("LPCWSTR", UNICODE_STR)
        self.addSuportedType("LPWSTR", UNICODE_STR)

        self.setPluginType("String")

    def guessValues(self, rawValue):
        """
        Guess string values
        """
        minLength = 5  # The minimal string length

        value = idc.GetString(rawValue, strtype=idc.ASCSTR_C)
        if value is not None and len(value) >= minLength:
            value, raw_value = self.normalize_raw_value(value)
            self.addParsedvalue(value, 1, "ASCII C-String", raw_value)

        value = idc.GetString(rawValue, strtype=idc.ASCSTR_UNICODE)
        if value is not None and len(value) >= minLength:
            value, raw_value = self.normalize_raw_value(value)
            self.addParsedvalue(value, 1, "Ascii Unicode String", raw_value)

        value = idc.GetString(rawValue, strtype=idaapi.ASCSTR_PASCAL)
        if value is not None and len(value) >= minLength:
            value, raw_value = self.normalize_raw_value(value)
            self.addParsedvalue(value, 1, "Ascii Pascal string", raw_value)

        value = idc.GetString(rawValue, strtype=idaapi.ASCSTR_LEN2)
        if value is not None and len(value) >= minLength:
            value, raw_value = self.normalize_raw_value(value)
            self.addParsedvalue(value, 1, "Ascii String (Len2)", raw_value)

        value = idc.GetString(rawValue, strtype=idaapi.ASCSTR_LEN4)
        if value is not None and len(value) >= minLength:
            value, raw_value = self.normalize_raw_value(value)
            self.addParsedvalue(value, 1, "Ascii String (Len4)", raw_value)

        value = idc.GetString(rawValue, strtype=idaapi.ASCSTR_ULEN2)
        if value is not None and len(value) >= minLength:
            value, raw_value = self.normalize_raw_value(value)
            self.addParsedvalue(value, 1, "Ascii String (ULen2)", raw_value)

        value = idc.GetString(rawValue, strtype=idaapi.ASCSTR_ULEN4)
        if value is not None and len(value) >= minLength:
            value, raw_value = self.normalize_raw_value(value)
            self.addParsedvalue(value, 1, "Ascii String (ULen4)", raw_value)

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
        if self.type_params == ASCII_STR:
            value = idc.GetString(rawValue, strtype=idc.ASCSTR_C)
            description = "ASCII C-String"

        elif self.type_params == UNICODE_STR:
            value = idc.GetString(rawValue, strtype=idc.ASCSTR_UNICODE)
            description = "Unicode String"

        else:
            return

        value, raw_value = self.normalize_raw_value(value)
        self.addParsedvalue(value, 0, description, raw_value)

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









