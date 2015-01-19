__author__ = 'lioro'

from DIE.Lib.DataPluginBase import DataPluginBase
from ctypes import *
from win32api import *
from win32con import *

import idc

ObjectTypeInformation = 2
ObjectNameInformation = 1
ObjectBasicInformation = 0

isWin64Process = False  # Set if the IDA process is 64-bit

def tohex(val, nbits=32):
    return hex((val + (1 << nbits)) % (1 << nbits))

class HandleParser(DataPluginBase):
    """
    A parser for boolean values
    """

    def __init__(self):
        super(HandleParser, self).__init__()

        self.setPluginType("HANDLE")

    def registerSupportedTypes(self):
        """
        Register string types
        @return:
        """
        self.addSuportedType("HANDLE", 0)
        self.addSuportedType("HGLOBAL", 0)
        self.addSuportedType("HMODULE", 0)

    def matchType(self, type):
        """
        Check if given type is of a string type
        @param type: IDA type_info_t object
        @return: True if given type is a string type otherwise False
        """
        return self.checkSupportedType(type)

    def parseValue(self, rawValue):
        """
        Parse the string value
        @return:
        """
        try:

            if rawValue == 0:
                return None

            handle = rawValue
            processId = idc.GetEventPid()

            #TODO: create "custom" init

            self.processHandle = OpenProcess(PROCESS_DUP_HANDLE,0,processId)

            myHandle = DuplicateHandle(self.processHandle.handle,handle,GetCurrentProcess(),0,0,DUPLICATE_SAME_ACCESS)
            NtQueryObject = windll.ntdll.NtQueryObject

            # Get name information
            size_out_name = c_int(0)
            res_name = NtQueryObject(myHandle.handle, ObjectNameInformation,0,0,byref(size_out_name))
            buf_name = create_string_buffer(size_out_name.value)
            res_name = NtQueryObject(myHandle.handle, ObjectNameInformation,buf_name,size_out_name,byref(size_out_name))

            # Get type information
            size_out_type = c_int(0)
            res_type = NtQueryObject(myHandle.handle, ObjectTypeInformation,0,0,byref(size_out_type))
            buf_type = create_string_buffer(size_out_type.value)
            res_type = NtQueryObject(myHandle.handle, ObjectTypeInformation,buf_type,size_out_type,byref(size_out_type))

            if (isWin64Process):
                handle_name = buf_name.raw[0x10:][::2].split("\x00")[0]
                handle_type = buf_type.raw[0x68:][::2].split("\x00")[0]
            else:
                handle_name = buf_name.raw[0x8:][::2].split("\x00")[0]
                handle_type = buf_type.raw[0x60:][::2].split("\x00")[0]
                
            #print "handle:%s \n\t name:%s \n\t res_name:%s \n\t buf_name:%s \n\t type:%s \n\t res_type:%s \n\t buf_type:%s \n" % (hex(handle), handle_name, tohex(res_name), list(buf_name), handle_type, tohex(res_type), list(buf_type))

            if handle_name is None or handle_name == "":
                handle_name = "Nameless Handle"

            self.addParsedvalue(handle_name, 0,handle_type, hex(rawValue))

        except Exception as ex:
            #self.logger.error("Handle parser failed for handle %s: %s", hex(rawValue), ex)
            return False












