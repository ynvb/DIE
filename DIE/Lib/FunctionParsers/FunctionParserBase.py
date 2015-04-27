__author__ = 'yanivb'

import logging
from DIE.Lib.IDATypeWrapers import Function, FuncArg
from DIE.Lib.DebugValue import *
from DIE.Lib.IDAConnector import get_sp, get_stack_element_size
import DIE.Lib.DataParser

class FunctionParserBase(object):
    """
    Base class for function parsers.
    Provides all functionality required to parse function arguments.
    """

    def __init__(self, function):
        """

        @param function: a
        @raise TypeError:
        """

        self.logger = logging.getLogger(__name__)
        self.dataParser = DataParser.getParser()    # Data Parser (ParserDataPlugin Manager) instance

        self.__func_args = {}          # A dictionary with the argument index as key. the dictionaries value is an array
                                       # who`s first element is the relevant data parser, and second element is the data
                                       # parsers (optional) arguments.
                                       #
                                       #        /- Arg Index -\ /- DataParser -\ /- Optional Params -\
                                       #        |      0      | | StringParser | |      (None)       |
                                       #        |      3      | | HandleParser | |     (16,0x2)      |
                                       #        |     ...     | |     ...      | |       ...         |
                                       #        \             / \              / \                   /
                                       #
                                       # If an argument index exist in this list, it will be parsed using the
                                       # defined DataParser only.
                                       # If an argument index does not exist, or doesnt have any DataParser
                                       # assigned, Standard DataParser lookup will take place in order to parse it.

        if not isinstance(function, Function):
            raise TypeError("Expected function instance, received %s", function.__class__)

        self.function = function    # The function to be parsed

    def parse_function_args_call(self):
        """
        Parse all function arguments upon function call
        *Abstract function. this function should be implimented by all subclasses*
        @return: an array of parsed argument values
        """
        raise NotImplemented("abstract function 'parse_function_args' was not implimented")

    def parse_function_args_ret(self, parsed_arg_vector):
        """
        Parse all function arguments upon function return
        @param parsed_arg_vector: an array of previously parsed arg values
        @return: A tuple of (parsed_arg_vec, ret_arg)
                 parsed_arg_ved - an array of "freshly" parsed argument values
                 ret_arg - parsed value of the return argument
        """
        try:
            if parsed_arg_vector is None:
                raise TypeError("No argument vector value found.")

            if len(parsed_arg_vector) != self.function.argNum:
                raise RuntimeError("Argument vector expected size is %d, size sent is: %s",
                                   self.function.argNum,
                                   len(parsed_arg_vector))

            arg_values = []

            for arg_index, parsed_arg in enumerate(parsed_arg_vector):
                if not isinstance(parsed_arg, DebugValue):
                    raise TypeError("Invalid parsed argument value")

                arg_values.append(self.__get_return_arg_value(arg_index,
                                                              parsed_arg.storetype,
                                                              parsed_arg.loc,
                                                              parsed_arg.type,
                                                              parsed_arg.name))

            ret_arg_value = None
            # If function return argument exist and is not VOID parser it as well.
            if self.function.retArg and not self.function.retArg.argtype.is_void():
                ret_arg_value = self.get_arg_value(self.function.retArg)

            return arg_values, ret_arg_value

        except Exception as ex:
            # TODO: format all the exceptions to get the stacktrace and not just an error. If relevant...
            self.logger.error("Could not parse function %s return arguments: %s", self.function.funcName, ex)
            return None

    def get_parser(self, parser_name):
        """
        Get a parser from data parser plugins
        @param parser_name: the parser name to retrieve
        @return: if parser was found returns a DataParser plugin object. otherwise returns None.
        """

        if parser_name is None:
            return None

        data_parser = self.dataParser.pManager.getPluginByName(parser_name, "ParserPlugins")
        if data_parser is None:
            self.logger.error("could not locate parser %s", parser_name)
            return None

        if data_parser.plugin_object is None:
            self.logger.error("no plugin object found for parser %s", parser_name)
            return None

        return data_parser.plugin_object

    def lookup_custom_parser(self, arg_index):
        """
        Lookup a custom parser for an argument.
        @param arg_index: Argument index.
        @return: If a parser was found for the argument index an array of [DataParser plugin object, *args) is returned.
                 otherwise None is returned
        """
        if arg_index in self.__func_args:
            parser_name, parser_params = self.__func_args[arg_index]
            if parser_name is not None:
                parser_plugin_obj = self.get_parser(parser_name)
                if parser_plugin_obj is not None:
                    return [parser_plugin_obj, parser_params]

        return None

    def add_custom_parser(self, arg_index, parser_name, *args):
        """
        Add a custom data parser for a argument
        @param arg_index: Argument index (0 based. -1 => return argument)
        @param parser_name: Name of the data parser to use when parsing this argument
        @param *args: Any additional parameters required by the parser
        @return: True if custom parser was successfully added, otherwise False
        """
        if arg_index < -1:
            raise TypeError("Invalid Argument index")

        if parser_name is None:
            self.logger.error("Cannot add custom parser for argument %d - No parser name provided")
            return False

        if arg_index in self.__func_args:
            self.logger.error("Cannot add a custom parser for argument index %d, since it already"
                              "has a custom parser assigned.", arg_index)
            return False

        self.__func_args[arg_index] = [parser_name, args]  # Add custom parser to dictionary

    def remove_custom_parser(self, arg_index):
        """
        Remove a custom parser from an argument
        @param arg_index: Argument index (0 based. -1 => return argument)
        @return: True if the custom parser was successfully removed, otherwise False
        """
        if arg_index < -1:
            raise TypeError("Invalid Argument index")

        if not arg_index in self.__func_args:
            self.logger.error("Cannot remove custom parser since argument index %d does not exist", arg_index)
            return False

        del self.__func_args[arg_index]  # Remove custom parser from dictionary

    def get_arg_value(self, arg):
        """
        Get a specific argument value
        @param arg_index: Argument index (0 based. -1 => return argument)
        @param arg: Function argument object (type: FuncArg)
        @return: DebugValue object containing the current argument value. Returns None on failure
        """

        if not isinstance(arg, FuncArg):
            raise TypeError("Invalid function argument.")

        arg_type = None      # argument type_info_t
        loc = None           # If passe via stack - stack offset, if passed via register - register name
        store_type = None    # Argument passing method (e.g passed via register\stack)

        if not arg.isGussed:
            arg_type = arg.argtype

        # If argument is passed via register
        if arg.isReg():
            store_type = REG_VAL
            loc = arg.registerName()

        # If argument is passed via stack
        if arg.isStack():
            store_type = MEM_VAL
            return_adr_size = get_stack_element_size()       # stack return address size
            loc = get_sp() + return_adr_size + arg.offset()  # Absolute stack argument address

        if store_type is None:
            raise RuntimeError("Unhandled or malformed argument passing type")

        parser = None

        # Lookup a specific argument parser for this argument
        lookup_res = self.lookup_custom_parser(arg.argNum)
        if lookup_res is not None:
            [parser, parser_params] = lookup_res

        return DebugValue(store_type,
                          loc,
                          arg_type,
                          arg.name(),
                          custom_parser=parser)

    def __get_return_arg_value(self, arg_index, store_type, loc, type, name):
        """
        Get an argument value of a previously parsed argument
        @param arg_index: Argument index
        @param store_type: REG_VAL\MEM_VAL
        @param loc: Argument location
        @param type: Argument type
        @param name: Argument name
        @return: DebugValue object containing the current argument value. Returns None on failure
        """

        parser = None

        # Lookup a specific argument parser for this argument
        lookup_res = self.lookup_custom_parser(arg_index)
        if lookup_res is not None:
            parser, parser_params = lookup_res

        return DebugValue(store_type,
                          loc,
                          type,
                          name,
                          custom_parser=parser)




























