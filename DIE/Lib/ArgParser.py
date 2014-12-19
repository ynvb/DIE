__author__ = 'yanivb'

from DIE.Lib.DebugValue import *


ON_RETURN = 0
ON_CALL = 1
ON_BOTH = 2

class ArgParser():
    """
    DIE Function Argument parser.
    """

    def __init__(self):

        self.logger = logging.getLogger(__name__)
        self.dataParser = DataParser.getParser()  # Data Parser (ParserDataPlugin Manager) instance
        self.ret_arg_parser = None                # A DataPluginBase parser for parsing the function`s return value.
        self.custom_parsers_list = {}             # See below.

        # custom_parser_list is a dictionary with the function argument index set as the key.
        # each key`s value consists of a tuple with the following format:
        #   (Valid_On, Parser) ->
        #     -> Valid_On: indicates when is this parser valid (on function call, on function return or both)
        #     -> Parser:   is a DataPluginBase instance that should be used to parse the specific argument.

    def set_custom_arg_parser(self, arg_index, valid_on, parser_name):
        """
        Set a custom parser for a function argument

        @param arg_index: argument (0-based) index. -1 indicates return argument.
        @param valid_on: should this argument be parsed on function return(=0)\call(=1)\both(=2)
        @param parser_name: a DataPlugin parser name to be used to parse the argument.
        """
        if not self._validate_valid_on(valid_on):
            self.logger.error("illegal valid_on value %d. values must be in range 0-2", valid_on)
            return False

        if not self._validate_parser_name(parser_name):
            self.logger.error("illegal or empty parser name provided: %s", parser_name)
            return False

        if not self._validate_index(arg_index):
            self.logger.error("illegal argument index %d.", arg_index)

        parser_plugin = self.dataParser.pManager.getPluginByName(parser_name, "ParserPlugins")
        if parser_plugin is None:
            self.logger.error("could not locate parser %s", parser_name)
            return False

        if parser_plugin.plugin_object is None:
            self.logger.error("no plugin object found for parser %s", parser_name)
            return False

        # get plugin object
        parser_plugin = parser_plugin.plugin_object

        # If return argument
        if arg_index == -1:
            if self.ret_arg_parser is not None:
                self.logger.info("changing existing parser for return argument")

            # Set the parser for return argument
            self.ret_arg_parser = parser_plugin
            return True

        # Are we changing an existing parser? (used for logging only.)
        if self.custom_parsers_list is not None:
            if arg_index in self.custom_parsers_list:
                self.logger.info("changing existing parser for argument index %d", arg_index)

        # Set the parser for this argument
        parser_tuple = (valid_on, parser_plugin)
        self.custom_parsers_list[arg_index] = parser_tuple
        return True

    def get_custom_arg_parser(self, arg_index, current_pos):
        """
        Get a custom parser for a specific function argument

        @param arg_index: The argument (0-based) index. -1 indicates return argument
        @param current_pos: Current function position in which this plugin has be invoked (on return(=0)\on call(=1))
        @return: Returns custom DataPlugin parser if exists, otherwise returns None
        """
        if not self._validate_index(arg_index):
            self.logger.error("illegal argument index %d.", arg_index)
            return False

        if arg_index == -1:
                return self.ret_arg_parser

        if not self._validate_valid_on(current_pos):
            self.logger.error("illegal cur_pos value %d. values must be in range 0-2", current_pos)
            return False

        if arg_index in self.custom_parsers_list:
            (valid_on, parser_plugin) = self.custom_parsers_list[arg_index]
            if valid_on == ON_BOTH or valid_on == current_pos:
                return parser_plugin

        return None

    def remove_custom_arg_parser(self, arg_index):
        """
        Removes custom parser from specific function argument

        @param arg_index: The argument (0-based) index. -1 indicates return argument
        @return: Returns True if custom parser was successfully removed, otherwise returns False
        """

        if not self._validate_index(arg_index):
            self.logger.error("illegal argument index %d.", arg_index)
            return False

        if arg_index == -1:
            self.ret_arg_parser = None
            return True

        if arg_index in self.custom_parsers_list:
            del self.custom_parsers_list[arg_index]
            return True

        return False

    def get_arg_value(self, arg_index, store_type, loc, argtype, argname, cur_pos=ON_BOTH):
        """
        Get an argument runtime value
        """
        try:
            custom_parser = self.get_custom_arg_parser(arg_index, cur_pos)
            argValue = DebugValue(store_type, loc, argtype, argname, custom_parser=custom_parser)
            return argValue

        except Exception as ex:
            raise RuntimeError("Error: Could not retrieve argument call value: %s" % ex)


    def _validate_index(self, index):
        """
        Validate index value
        @param index: index value to validate
        @return: True if validated otherwise False
        """
        if index < -1 or index > 1000:
            return False

        return True

    def _validate_valid_on(self, valid_on):
        """
        Validate valid_on value
        @param valid_on: valid_on value to validate
        @return: True if validated otherwise False
        """
        if valid_on <0 or valid_on > 2:
            return False

        return True

    def _validate_parser_name(self, parser_name):
        """
        Validate parser name value
        @param parser_name: parser_name value to validate
        @return: True if validated otherwise False
        """
        if parser_name is None or parser_name == "":
            return False

        return True






















