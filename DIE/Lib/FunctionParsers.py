import DIE.Lib.ArgParser as ArgParser

__author__ = 'yanivb'

import logging

class _FunctionParsers():
    """
    A class which contains the data and methods required to parse function arguments.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        print "Function Parsers class initiated"

        # custom_arg_parser_list is a dictionary containing custom function argument parsers.
        # the dictionary key is a concatenation of the function name and the call location.
        # for example ("GetRegKey481223"), or in case of no call location ("GetRegKey")
        # each dictionary value is an argument parser (instance of ArgParser) used to parse function arguments.
        self.custom_arg_parser_list = {}

        #TODO: for debug only, implement XML data loading:
        #self.add_custom_arg_parser("kernel32_MultiByteToWideChar", 1, "BoolParser", ArgParser.ON_CALL, 4372983)

    def get_arg_parser(self, func_name, loc):
        """
        Get a function argument parser class
        @param func_name: function name
        @param loc: location of function call instruction
        @return: Returns a function argument class (ArgParser instance) that can be used to parse the function args.
        """
        key = self._make_list_key(func_name, loc)

        # Try returning a custom parser for function\location.
        if key in self.custom_arg_parser_list:
            return self.custom_arg_parser_list[key]

        # If not found, try looking for a custom parser for this function (all locations)
        elif func_name in self.custom_arg_parser_list:
            return self.custom_arg_parser_list[func_name]

        # if no custom parser found, return default parser
        else:
            return ArgParser.ArgParser()

    def load_arg_parsers(self):
        """
        Load custom argument parsers from configuration file
        """
        raise NotImplemented

    def save_arg_parsers(self):
        """
        Save custom argument parsers to the configuration file
        @return:
        """

    def add_custom_arg_parser(self, function_name, arg_index, parser_name, valid_on=ArgParser.ON_BOTH, function_location=None):
        """
        Add a custom arg parser
        @param function_name: The function name to parse
        @param arg_index: function argument (0 based) index. -1 indicates return value.
        @param parser_name: name of a custom parser to use
        @param valid_on: when should be parser be used ( on function return(=0)\call(=1)\both(=2) )
        @param function_location: The function 'call' location to parse the arg (default: parse always)
        @return: true if custom parser was successfully added, otherwise False
        """
        try:
            if self.custom_arg_parser_list is None:
                self.logger.error("missing custom_arg_parser_list")
                return False

            key = self._make_list_key(function_name, function_location)

            if key in self.custom_arg_parser_list:

                # Check if current location based parser override a parent parser (non-location dependent)
                if function_location is not None:
                    parent_key = self._make_list_key(function_name, None)
                    if parent_key in self.custom_arg_parser_list:
                        self.logger.info("Setting current parser for function: %s "
                                     "at location: %s will override existing parser for this function "
                                     "(set to be used in any location",
                                     function_name,
                                     function_location)

                arg_parser = self.custom_arg_parser_list[key]
            else:
                arg_parser = ArgParser.ArgParser()

            arg_parser.set_custom_arg_parser(arg_index, valid_on, parser_name)
            self.custom_arg_parser_list[key] = arg_parser
            return True

        except Exception as ex:
            self.logger.error("Could not add custom argument parser for function %s at location %s: %s",
                          function_name,
                          function_location,
                          ex)
            return False

    def remove_custom_arg_parser(self, function_name, arg_index, function_location=None):
        """
        Remove a custom arg parser
        @param function_name: The function name to parse
        @param arg_index: function argument (0 based) index. -1 indicates return value.
        @param function_location: The function 'call' location to parse the arg (default: parse always)
        @return: True if custom parser was successfully removed, otherwise False.
        """
        try:
            if not self.custom_arg_parser_list:
                    self.logger.error("missing custom_arg_parser_list (value is None)")
                    return False

            key = self._make_list_key(function_name, function_location)

            if key in self.custom_arg_parser_list:
                arg_parser = self.custom_arg_parser_list[key]
                if arg_parser.remove_custom_arg_parser(arg_index):
                    return True

            return False

        except Exception as ex:
            self.logger.error("Failed to remove custom arg parser for "
                          "function: %s, argument: %s, location: %s. %s",
                          function_name, arg_index, function_location, ex)
            return False


    def _make_list_key(self, func_name, func_loc):
        """
        Create a key used for indexing the custom_arg_parser_list.
        @param func_name: function name
        @param func_loc: function location (None if no location available)
        @return: the key to be used as index in the custom_arg_parser_list.
        """
        if func_name is None or func_name == "":
            self.logger.error("Function name is required")
            return False

        if func_loc is None:
            func_loc = ""
        else:
            func_loc = str(func_loc)

        # Returned key is a concatenation of function name and function location
        return func_name + func_loc


###########################################################################################
#       Singleton implementation (The python way... ;)
###########################################################################################

_function_parser = _FunctionParsers()

def get_function_parsers():
    return _function_parser



