__author__ = 'yanivb'

class FuncCallExceedMax(Exception):
    """
    Function call exceeded the mzx number of defined calls.
    """
    pass

class NewCodeSectionException(Exception):
    """
    New code section detected exception
    """
    def __init__(self, section_start=None, section_end=None):
        """
        @param section_start: New code section start address
        @param section_end: New code section end address
        """
        self.section_start = section_start
        self.section_end = section_end

class DbFileMismatch(Exception):
    """
    Database size has exceeded
    """
    pass


