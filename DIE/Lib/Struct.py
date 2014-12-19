__author__ = 'yanivb'

#from idaapi import *
import idaapi
import logging

class StructElement():
    """
    Struct Element
    """

    def __init__(self, size, offset, type, name=None, comment=None):
        """
        Struct element class
        @param size: Size of element
        @param offset: Element offset within the struct
        @param type: Element type
        @param name: Element name string
        @param comment: Element comment (Optional)
        """
        self.logger = logging.getLogger(__name__)

        self.name = name
        self.comment = comment
        self.offset = offset
        self.size = size

        self.type = type

    def get_name(self):
        """
        Get struct element`s name
        """
        if self.name is None or self.name == "":
            return "field_%d" % self.offset

        return self.name

    def type_name(self):
        """
        Get type name (int, char, LPCSTR etc.)
        """
        idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, self.type, '', '')


class Struct():
    """
    Struct class
    """

    def __init__(self, type):

        self.logger = logging.getLogger(__name__)

        self.name = ""
        self.size = 0
        self.element_num = 0
        self.is_union = False

        self.elements = []

        self.type_info = type
        self.udt_type_data = idaapi.udt_type_data_t()


        try:
            if self.getStructData():
                self.getElements()

        except:
            self.logger.error("Error while extracting struct data: %s",
                          idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, type, '', ''))
            return False


    def getStructData(self):
        """
        Extract the struct data from tinfo_t object and populate all relevant class properties.
        @return: True if successful, otherwise False
        """

        try:
            if self.type_info.is_udt():
                if self.type_info.get_udt_details(self.udt_type_data):

                    self.name = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, self.type_info, '', '')
                    self.size = self.udt_type_data.size
                    self.element_num = len(self.udt_type_data)
                    self.is_union = self.udt_type_data.is_union

                    return True

            return False

        except Exception as ex:
            self.logger.error("Error while enumerating struct: %s", ex)
            return False

    def getElements(self):
        """
        Get struct elements
        """

        for element_index in xrange(0, self.element_num):
            cur_element = self.udt_type_data[element_index]
            name = None
            comment = None

            if cur_element.name is not None:
                name = cur_element.name

            if cur_element.cmt is not None:
                comment = cur_element.cmt

            strcut_elem = StructElement(cur_element.size,
                                        cur_element.offset,
                                        cur_element.type,
                                        name,
                                        comment)

            self.elements.append(strcut_elem)

















