

class DieException(Exception):
    pass

class FuncCallExceedMax(DieException):
    """
    Function call exceeded the mzx number of defined calls.
    """
    pass

class DbFileMismatch(DieException):
    """
    Database size has exceeded
    """
    pass

class DieNoFunction(DieException):
    pass

class DieCallStackPushError(DieException):
    """
    Error pushing function to DIE callstack
    """

    def __init__(self, ea, function_name=None):
        """
        @param ea: Function address
        """
        self.ea = ea
        self.function_name = function_name

class DieCallStackPopError(DieException):
    """
    Error poping function from DIE callstack
    """
    pass

class DieMemNotLoaded(DieException):
    """
    An attempt was made to access an unloaded memory address
    """
    pass

class DieLibraryPreviouslyLoaded(DieException):
    """
    Library was previously loaded
    """
    pass

class DieThunkFunctionDetected(DieException):
    """
    Thunk function detected
    """
    pass