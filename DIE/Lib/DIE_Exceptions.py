__author__ = 'yanivb'

class FuncCallExceedMax(Exception):
    """
    Function call exceeded the mzx number of defined calls.
    """
    pass

class DbFileMismatch(Exception):
    """
    Database size has exceeded
    """
    pass


