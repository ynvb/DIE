__author__ = 'yanivb'
"""
Instruction parsing utility
"""
from idaapi import *
from idautils import *
from idc import *

import logging

class InstructionParserX86():
    """
    An X86 instruction parsing class
    """

    def __init__(self):
        """
        Ctor
        """
        self.logger = logging.getLogger(__name__)

        self.type = "x86 Instruction Parser"
        self.inf = idaapi.get_inf_structure()

    def get_native_size(self):
        """
        Get the native OS size
        @return: 16, 32, 64 value indicating the native size or None if failed.
        """
        try:
            if self.inf.is_32bit():
                return 32
            elif self.inf.is_64bit():
                return 64
            else:
                self.logger.info("Native size is neither 32 or 64 bit. assuming 16 bit.")
                return 16

        except Exception as ex:
            self.logger.error("Could not Could not retrieve native OS size: %s", ex)
            return None

    def get_proc_type(self):
        """
        Get processor type
        @return: Returns the processor type or None on failure.
        """
        try:
            return self.inf.procName()

        except Exception as ex:
            self.logger.error("Could not retrieve processor type: %s", ex)
            return None

    # TODO: Change this to be architecture independent
    def is_call(self, ea):
        """
        Check if the current instruction a CALL instruction
        """
        mnem = GetMnem(ea)
        if re.match('call\s+far prt', mnem):  return None
        return re.match('call', mnem)

    # TODO: Change this to be architecture independent
    def is_ret(self, ea):
        """
        Check if the current instruction a RET instruction
        """
        mnem = GetMnem(ea)
        return re.match('ret', mnem)

    # TODO: Change this to be architecture independent
    def get_cur_ea(self):
        """
        Return the current effective address
        """
        nativeSize = self.get_native_size()

        if nativeSize is 16:
            return GetRegValue('IP')

        if nativeSize is 32:
            return GetRegValue('EIP')

        if nativeSize is 64:
            return GetRegValue('RIP')

    # TODO: Change this to be architecture independent
    def get_ret_adr(self):
        """
        Get the return address for the current function
        """
        nativeSize = self.get_native_size()

        if nativeSize is 16:
            nextInst = DbgWord(GetRegValue('SP'))  # Address of instruction following the CALL

        if nativeSize is 32:
            nextInst = DbgDword(GetRegValue('ESP'))  # Address of instruction following the CALL

        if nativeSize is 64:
            nextInst = DbgQword(GetRegValue('RSP'))  # Address of instruction following the CALL

        prev_addr, farref = idaapi.decode_preceding_insn(nextInst)  # Get previous instruction

        return prev_addr

    # TODO: Change this to be architecture independent
    def get_sp(self):
        """
        Get the current stack pointer address
        """
        return GetRegValue('ESP')

    def get_adrs_mem(self, ea):
        """
        Get the memory at address according to native size (16, 32 or 64 bit)
        """

        # Verify EA
        if not idc.isEnabled(ea):
            return None

        nativeSize = self.get_native_size()

        if nativeSize is 16:
            return DbgWord(ea)

        if nativeSize is 32:
            return DbgDword(ea)

        if nativeSize is 64:
            return DbgQword(ea)

    # Ask hex-rays how can this be done a bit more gracefully..
    def regOffsetToName(self, offset):
        """
        Get register name from an offset to ph.regnames
        """
        regName = idaapi.ph_get_regnames()[offset]

        if not offset in range(0,7):
            return regName.upper()

        if self.get_native_size() is 16:
            return regName.upper()

        if self.get_native_size() is 32:
            return "E" + regName.upper()

        if self.get_native_size() is 64:
            return "R" + regName.upper()

        return ValueError("Failed to retrieve register name.")

    def get_stack_element_size(self):
        """
        Get size of a stack element
        @return: size of a stack element (in bytes)
        """
        return self.get_native_size()/8











