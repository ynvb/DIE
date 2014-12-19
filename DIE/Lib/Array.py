__author__ = 'yanivb'

import idaapi
import logging

class Array():
    """
    Array Class
    """

    def __init__(self, type):

        self.logger = logging.getLogger(__name__)

        self.type_info = type
        self.array_type_data = idaapi.array_type_data_t()

        self.element_type = None
        self.element_num = 0
        self.element_size = 0

        self.elements = []

        # Extract array data
        self.get_array_data()

    def get_array_data(self):
        """
        Extract the array data from tinfo_t object and populate all relevant class properties.
        @return: True if successful, otherwise False
        """

        try:
            if self.type_info.is_array():
                if self.type_info.get_array_details(self.array_type_data):
                    self.element_type = self.array_type_data.elem_type
                    self.element_num = self.array_type_data.nelems
                    self.element_size = self.element_type.get_size()
                    return True

            return False

        except Exception as ex:
            self.logger.error("Error while getting array data: %s", ex)
            return False





