

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