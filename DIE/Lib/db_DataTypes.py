

class dbFuncArg():
    """
    Function Argument
    """
    def __init__(self, arg_name, arg_type, arg_index, is_stack):

        self.name = arg_name
        self.type = arg_type
        self.arg_index = arg_index

        self.is_stack = is_stack
        self.is_register = not is_stack

class dbFunction():
    """
    Static Function Data
    """
    def __init__(self, function_name, function_start, function_end, proto_ea, arg_num, is_lib_func, lib_name):

        self.function_name = function_name
        self.function_start = function_start
        self.function_end = function_end
        self.proto_ea = proto_ea
        self.arg_num = arg_num

        self.is_lib_func = is_lib_func
        self.lib_name = lib_name  # Containing library function name

        self.args = []
        self.ret_arg = None

        self.function_contexts = []

    def __getkey__(self):
        arg_num = self.arg_num
        if self.arg_num is None:
            arg_num = 0

        function_start = self.function_start
        if self.function_start is None:
            function_start = 0

        function_end = self.function_end
        if self.function_end is None:
            function_end = 0

        return "%s, %d, %d, %d" % (self.function_name, arg_num, function_start, function_end)

    def __hash__(self):
        return hash(self.__getkey__())

    def __eq__(self, other):
        return (self.function_name, self.arg_num, self.function_start, self.function_end) == \
                (other.function_name, other.arg_num, other.function_start, other.function_end)

    def __ne__(self, other):
        return not __eq__(self, other)

class dbFunction_Context():
    """
    Function Runtime Context
    """
    def __init__(self, id, call_reg_state, ret_reg_state, calling_ea, parent_func_ctxt_id, is_indirect, is_new_func, calling_func_name, total_proccess_time, thread_id):

        self.id = id
        self.function = None

        self.call_values = []
        self.ret_values = []
        self.ret_arg_value = None

        self.call_reg_state = call_reg_state
        self.ret_reg_state = ret_reg_state

        self.calling_ea = calling_ea
        self.calling_func_name = calling_func_name

        self.parent_func_ctxt_id = parent_func_ctxt_id

        self.is_indirect = is_indirect
        self.is_new_func = is_new_func

        self.thread_id = thread_id

        self.total_process_time = total_proccess_time

    def __repr__(self):
        return "<dbFunction_Context(id=%s, parent_id=%s)>" % (self.id, self.parent_func_ctxt_id)


class dbDebug_Values():
    """
    Dynamically Acquired Values
    """

    def __init__(self, raw_value, type_name, name, is_definitely_parsed, deref_depth):

        self.raw_value = raw_value
        self.type = type_name
        self.name = name

        self.parsed_values = []

        self.nested_values = []
        self.reference_flink = None
        self.reference_blink = None

        self.function_context = None

        self.derref_depth = deref_depth

        self.best_val_id = None  # Parsed_val_id of the most definite (lowest scoring) parsed value.
        self.is_definitely_parsed = is_definitely_parsed


class dbParsed_Value():
    """
    Dynamically Parsed Value
    """

    def __init__(self, data, description, raw_val, score, type):

        self.data = data
        self.description = description
        self.raw = raw_val
        self.type = type

        self.score = score

        self.dbgValues = []

    def __getkey__(self):
        if self.data is not None:
            data = self.data
        else:
            data = ""

        if self.description is not None:
            description = self.description
        else:
            description = ""

        if self.raw is not None:
            raw = self.raw
        else:
            raw = ""

        return "%s%s%s" % (data, description, raw)

    def __hash__(self):
        return hash(self.__getkey__())

    def __eq__(self, other):
        return (self.data, self.description, self.raw) == (other.data, other.description, other.raw)

    def __ne__(self, other):
        return not __eq__(self, other)

class dbThread():
    """
    Runtime Thread
    """

    def __init__(self, thread_num):

        self.thread_num = thread_num
        self.cfg = []

class dbRun_Info():
    """
    Runtime Info
    """

    def __init__(self, start_time, end_time, filename, md5):

        self.start_time = start_time
        self.end_time = end_time
        self.file = filename
        self.md5 = md5

        self.threads = []      # TODO: LINK TO dbThreads

















