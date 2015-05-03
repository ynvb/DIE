

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
    pass

class DieCallStackPopError(DieException):
    """
    Error poping function from DIE callstack
    """
    pass