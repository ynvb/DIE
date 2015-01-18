__author__ = 'yanivb'

from FunctionParserBase import FunctionParserBase

class GenericFunctionParser(FunctionParserBase):
    """
    A generic function parser.
    This parser parses arguments by their index order.
    """

    def __init__(self, function):
        """
        @param function: A Function instance
        """
        super(GenericFunctionParser, self).__init__(function)

    def parse_function_args_call(self):
        """
        Parse function arguments by their indexes from arg0-argN
        @return: an array of parsed argument values (element type: DebugValue)
        """
        try:
            arg_values = []

            for arg in self.function.args:
                arg_values.append(self.get_arg_value(arg))

            return arg_values

        except Exception as ex:
            self.logger.error("Error while parsing function: %s", ex)
            return None





