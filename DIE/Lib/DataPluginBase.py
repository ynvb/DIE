

import logging

from yapsy.PluginManager import IPlugin
from DIE.Lib.ParsedValue import ParsedValue
from idaapi import *
from idautils import *
from idc import *


class DataPluginBase(IPlugin):
    """
    DIE Data Parser plugin base class.
    """

    name = ""
    version = 0
    description = ""
    author = ""
    is_activated = True

    supported_types = []       # supported_types hold tuples containing the supported type name and the type description
    type = None                # The value type (or None if unidentified).
    loc = None                 # The value (memory) location.
    rawValue = None            # The raw value to be parsed.
    parsedValues = []          # List of the parsed values.
    typeName_norm_cb = None    # Type name normalizer callback function

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.type_params = None      # Currently parsed type parameters

    def initPlugin(self, type_norm_callback=None):
        """
        Plguin Initialization
        @param type_norm_callback: a type name normalization callback function
        """
        idaapi.msg("Initializing plugin %s\n" % self.__class__)

        # Set type name normalization callback function
        if type_norm_callback is not None:
            self.typeName_norm_cb = type_norm_callback

        # Register supported types
        self.registerSupportedTypes()

    def guessValues(self, rawData):
        """
        "Abstract" method to be implemented by successors
        If type is not known, used to guess possible values matching rawData.
        @param rawData: Raw data who`s type should be guessed.
        """

    def matchType(self, type):
        """
        "Abstract" method to be implemented by successors.
        Checks if the type is supported by the current plugin.
        @param type: And type_info_t object to match
        @return: True if a match was found, otherwise False
        """
        return True

    def parseValue(self, rawData):
        """
        "Abstract" method to be implemented by successors.
        If type is known, Parses the value.
        @param rawData: Raw data who`s type should be parsed.
        @param type: IDA type_info_t object
        """

    def registerSupportedTypes(self):
        """
        A parser can register supported types in order to allow quick parser lookups.
        types are registered by their type name string value.
        registration should be made using self.addSuportedType()
        """

    def run(self, rawData, type, match_override=False):
        """
        Run Plugin
        @param rawData: the raw data to be parsed
        @param type: data type (None if unknown)
        @param match_override: set this flag in order to bypass the plugin type matching method.
        @return: DebugValue array with the parsed data
        """
        try:
            self.parsedValues = []  # Initialize parsed value list

            # If type was not recognized, try to guess the value.
            if type is None:
                self.guessValues(rawData)
                return self.parsedValues

            # If bypass match flag is set, force parsing.
            if match_override:
                self.parseValue(rawData)
                return self.parsedValues

            # Otherwise, if type matches the plugin parser type, run the parser logic.
            if self.matchType(type):
                self.parseValue(rawData)
                return self.parsedValues

        except Exception as ex:
            self.logger.exception("Error while running plugin: %s", ex)

    def setPluginType(self, type):
        """
        Set the plugin type string that will be associated with values parsed by this parser
        @param type: Type string (e.g. "INT")
        @return: True if type was successfully set, otherwise False.
        """
        try:
            self.type = type.lower()

        except Exception as ex:
            self.logger.exception("Setting plugin type failed: %s", ex)
            return False

    def addSuportedType(self, type_name, type_desc):
        """
        Add supported type to supported type list
        @param type_name: supported type name string
        @param type_desc: type description
        """
        # type description must not be Null. set to an empty string by default.
        try:
            if type_desc is None:
                type_desc = ""

            type_name = self.typeName_norm_cb(type_name)
            type_tuple = (type_name, type_desc)

            if not type_tuple in self.supported_types:
                self.supported_types.append(type_tuple)

        except Exception as ex:
            self.logger.exception("Failed to add supported type: %s", ex)


    def checkSupportedType(self, type):
        """
        Check if a type name string is supported
        @param type: IDA type_into_t object
        @return: True if type name is supported or otherwise False
        """
        try:
            tname = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, type, '', '')

            type_name = None
            if self.typeName_norm_cb is not None:
                type_name = self.typeName_norm_cb(tname)

            for (stype, sparams) in self.supported_types:
                if type_name == stype:
                    self.type_params = sparams
                    return True

            return False

        except Exception as ex:
            self.logger.exception("Error while checking for supported type: %s", ex)

    def getSupportedTypes(self):
        """
        Get a list in which each element is a tuple that contains:
            [1] supported type name
            [2] type description parameters
        (type names are strings stripped of all spaces, e.g "UNSIGNED CHAR *" will be returned as "UNSIGNEDCHAR*")
        @return: list of TypeTuples
        """
        if len(self.supported_types) > 0:
            return self.supported_types
        else:
            return None

    def addParsedvalue(self, value, score=0, description="NoN", raw=None):
        """
        Add a parsed value to the parsed value list
        """
        parsed_val = ParsedValue(value, description, score, raw, self.type)
        self.parsedValues.append(parsed_val)

    def getParsedValues(self):
        """
        Get the parsed values list
        @return: Parsed value list (with 'ParsedValue' element types)
        """
        return self.parsedValues







