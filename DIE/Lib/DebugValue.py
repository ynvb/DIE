from DIE.Lib import DieConfig, DataParser

__author__ = 'yanivb'

from DIE.Lib.InstParserUtil import *
import idaapi
from idc import *

#from DIE.Lib.Struct import *
#from DIE.Lib.Array import *

from DIE.Lib.IDATypeWrapers import Array, Struct

MEM_VAL = 0x01       # Memory based value
REG_VAL = 0x02       # Register based value

#MAX_DEREF_DEPTH = 3  # Maximal dereferencing depth.  $TODO: read from configuration

class DebugValue():
    """
    DebugValue class is responsible for reading the argument value.
    argument value is collected according to its type. e.g - Pointers will be dereferenced and the dereferenced value
    will be collected, struct will be enumerated and all their members will be collected, and arrays will be walked
    trough to collect their element value.

    DebugValue also collects 2 types of values for each collected element. The first is a raw native size value at the
    address (which is the default value used), And the second is a parsed value according to the argument type.
    (This is done by using the data parser plugins).

    Each argument may have only 1 raw value, but several possible parsed_values.
    Also each argument may have nested values (for supporting structs, unions, etc.)
    """

    def __init__(self,
                 storeType,
                 loc,
                 type="",
                 name="",
                 referringValue = None,
                 deref_depth=None,
                 custom_parser=None):
        """
        Ctor
        """
        self.logger = logging.getLogger(__name__)
        self.config = DieConfig.get_config()

        self.instParser = InstructionParserX86()

        self.storetype = storeType          # Value store location (memory\register)
        self.type = type                    # tinfo_t object.
        self.name = name                    # Value name
        self.loc = loc                      # Value location (if REG_VAL - register name, if MEM_VAL - memory address)
        self.rawValue = None                # Raw value at address

        self.parsedValues = []              # Possible value data list
        self.nestedValues = []              # Nested DebugValue(s) (if struct/union etc.)

        # Custom parser plugin for this value - if this value is set, no other parser will be attempted to parse
        # this value.
        self.custom_parser = custom_parser

        self.reference_flink = None             # For reference values, a pointer to the referred value.
        self.reference_blink = referringValue   # For reference values, a pointer to the referring value.

        # Set current maximal dereference depth for this argument.
        if deref_depth is None:
            self.derefrence_depth = self.config.max_deref_depth
        else:
            self.derefrence_depth = deref_depth     # de-reference depth

        # Collect runtime values!
        self.dataParser = DataParser.getParser()
        self.getRunetimeValues()

    def typeName(self):
        """
        Get the type human readable ASCII based name (in all upper case letters)
        """
        if self.type is None:
            return None

        typeName = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, self.type, '', '')
        if typeName is None or typeName == "":
            return None

        return typeName.upper()

    def is_container(self):
        """
        Checks if the local type is a container type.
        @rtype : True if this is a container type otherwise False
        """
        if self.type is not None:
            return self.type.is_struct()

        return False

    def is_array(self):
        """
        Check if the local type is an array type
        @return: True if this is an array type, otherwise False
        """
        if self.type is not None:
            return self.type.is_array()

        return False

    def dereference(self):
        """
        Get referenced value as DebugValue
        @rtype : True if dereference succeedes, otherwise False
        """
        # This can only be done safely when type is known
        if self.type is None:
            return None

        try:
            if self.type.is_ptr() and not self.type.is_pvoid():

                if self.derefrence_depth > 0:
                    ref_type = self.type.get_pointed_object()
                    ref_loc = self.getRawValue()
                    ref_blink = self
                    new_deref_depth = (self.derefrence_depth -1)

                    self.reference_flink = DebugValue(MEM_VAL,
                                                      ref_loc,
                                                      ref_type,
                                                      "-> ",
                                                      ref_blink,
                                                      deref_depth=new_deref_depth)

                return True

        except Exception as ex:
            self.logger.error("Failed to dereference %s: %s", self.typeName(), ex)
            return False
            
    def get_next_ref_val(self):
        """
        Get the next referenced value.
        @rtype : If reference value, returns the refered value object. otherwise returns None
        """
        if self.reference_flink is not None:
            return self.reference_flink
        
        return None

    def get_prev_ref_val(self):
        """
        Get the referring value.
        @rtype : If refereed by another value, returns the referring value object. otherwise returns None
        """
        if self.reference_blink is not None:
            return self.reference_blink

        return None

    def is_definitely_parsed(self):
        """
        Checks if a parsed value exist, and if it was definitely parsed.
        @rtype : Returns True if parsed value exist and was not guessed, otherwise returns False
        """
        if self.parsedValues is None:
            return False

        if len(self.parsedValues) > 0:
            for parsed_val in self.parsedValues:
                if not parsed_val.is_guessed():
                    return True

        return False

    def getRunetimeValues(self):
        """
        Get the runtime values according to the object location and store type.
        """
        try:
            if self.config.is_deref:
                self.dereference()

            # If value is a container (Struct\Union, etc.)
            if self.config.is_container:
                if self.is_container():
                    if self.derefrence_depth > 0:
                        struct = Struct(self.type)
                        struct_base_adrs = self.loc

                        if self.loc is not None:
                            new_ref_depth = (self.derefrence_depth - 1)
                            for element in struct.elements:  # Add nested DebugValue elements
                                element_val = DebugValue(MEM_VAL,
                                                         struct_base_adrs + element.offset,
                                                         element.type,
                                                         element.get_name(),
                                                         deref_depth=new_ref_depth)
                                self.nestedValues.append(element_val)

            # If value is an array
            if self.config.is_array:
                if self.is_array():
                    array = Array(self.type)
                    array_base_adrs = self.loc

                    if self.loc is not None:

                        prev_element = self
                        for element_index in xrange(0, array.element_num):  # TODO: maybe element_num -1 ?!
                            element_val = DebugValue(MEM_VAL,
                                                     array_base_adrs + (element_index*array.element_size),
                                                     array.element_type,
                                                     "[%d]" % element_index)

                            prev_element.reference_flink = element_val
                            prev_element = element_val

            if self.loc and self.storetype:
                if self.config.is_raw:
                    self.rawValue = self.getRawValue()

                if self.config.is_parse:
                    self.parsedValues = self.parseValue()

                return True

            else:
                #TODO: This is noisy. why? maybe this happens when value is NULL?
                #self.logger.error("Could not get runtime values for %s. no location\storetype information found", self.typeName())
                return False


        except Exception as ex:
            self.logger.error("Could not get runtime values for %s: %s", self.typeName(), ex)
            return False

    def getRawValue(self):
        """
        retrieve the raw value at the memory address
        @rtype : Returns the raw value at the given location or False if va;lue was not retrived.
        """
        try:
            # If memory value read native size bytes from ea
            if self.storetype == MEM_VAL:

                native_size = self.instParser.get_native_size()

                if native_size is 16:
                    return DbgWord(self.loc)
                if native_size is 32:
                    return DbgDword(self.loc)
                if native_size is 64:
                    return DbgQword(self.loc)

            # If register value, read register`s value
            if self.storetype == REG_VAL:
                return GetRegValue(self.loc)

            self.logger.error("Internal Error - storetype %d not supported.", self.storetype)
            return False

        except:
            raise RuntimeError("Failed to retrieve raw value for arg %s", self.typeName())
            return False

    def parseValue(self):
        """
        Run all plugins and attempt to parse the raw value
        """

        try:
            if self.rawValue is not None:
                return self.dataParser.ParseData(self.rawValue, self.type, self.loc, self.custom_parser)

        except Exception as e:
            print "Error while parsing value: %s" % e
            return None















