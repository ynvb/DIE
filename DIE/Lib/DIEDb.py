from collections import defaultdict, namedtuple, Counter

MAX_SCORE = 10


import logging
import pickle
import os
import operator

from DIE_Exceptions import DbFileMismatch

from DIE.Lib.db_DataTypes import dbDebug_Values, dbFuncArg, \
    dbFunction, dbFunction_Context, dbParsed_Value, dbRun_Info, dbThread

import idautils
import idaapi

class DIE_DB():
    """
    DIE Database class.
    """

    def __init__(self):

        self.logger = logging.getLogger(__name__)

        self.is_saved = True

        # Run info
        self.run_info = None

        # Debug data
        self.functions = {}
        self.function_args = {}
        self.function_contexts = {}
        self.threads = {}
        self.dbg_values = {}
        self.parsed_values = {}

        # Breakpoints
        self.bp_list = {}                   # BreakPoint dictionary
        self.excluded_modules = []          # A list of excluded modules
        self.excluded_funcNames = []        # A list of excluded function names
        self.excluded_bp_ea = []            # A list of excluded breakpoint addresses
        self.excluded_funcNames_part = []   # A list of excluded partial function names


    #############################################################################
    # Retrieve database items
    #############################################################################

    def get_functions(self):
        """
        Get a list of all functions in the db
        @return: A list of dbFunction objects
        """

        return self.functions.values()

    def get_function_by_name(self, function_name):
        """
        Get function by name
        @param function_name: function name
        @return: if function was found, returns function object of type dbFunction, otherwise returns None
        """

        functions = self.get_functions()
        for function in functions:
            if function.function_name == function_name:
                return function

        return None

    def get_function_context_list(self, function=None):
        """
        Get a list of function contexts
        @param function: Get a list of function contexts for this function only.
        @return:
        """
        if function is None:
            # Global function context list (for the entire db)
            cur_context_list = self.function_contexts
        else:
            # Local function context list (for a specific function)
            cur_context_list = function.function_contexts

        # No contexts found
        if cur_context_list is None:
            return []

        return self.function_contexts.values()


    def get_function_context_dict(self, function=None):
        """
        Get a dictionary of function contexts grouped by their calling_ea`s
        @param function: Get a function contexts dictionary for this function only.
        @return: A dictionary of function contexts grouped by their calling ea`s.
                 each dictionary node is a list of function contexts for this ea.
        """
        function_context_dict = defaultdict(list)

        if function is None:
            # Global function context list (for the entire db)
            cur_context_list = self.function_contexts
        else:
            # Local function context list (for a specific function)
            cur_context_list = function.function_contexts

        # No contexts found
        if cur_context_list is None:
            return function_context_dict

        for function_context_id in cur_context_list:
            current_context = self.function_contexts[function_context_id]
            function_context_dict[current_context.calling_ea].append(current_context)

        return function_context_dict

    def get_function_context(self, func_context_id):
        """
        Get a function context item based on it`s ID
        @param func_context_id: Function context ID
        @return: function context object (type: dbFunction_Context) or None for invalid ID.
        """
        return self.function_contexts.get(func_context_id, None)

    def get_function_name(self, function_id):
        """
        Get function  by function id
        @param function_id: a dbFunction object ID
        @return: Name of function or None on error
        """

        if not function_id in self.functions:
            return "UNKN_FUNCTION"

        function = self.functions[function_id]

        if function.function_name:
            return function.function_name

        if function.function_start:
            return "sub_%s" % hex(function.function_start)

        return "UNKN_FUNCTION"

    def get_call_values(self, function_context):
        """
        Get call value object list for a specific function context
        @param function_context: function_context object to retrieve call values from
        @return:
        """
        if not function_context:
            return []

        return [self.dbg_values[call_value_id] for call_value_id in function_context.call_values]


    def get_return_values(self, function_context):
        """
        Get return value object list for a specific function context
        @param function_context: function_context object to retrieve return values from
        @return:
        """
        if not function_context:
            return []

        return [self.dbg_values[ret_value_id] for ret_value_id in function_context.ret_values]


    def get_return_arg_value(self, function_context):
        """
        Get return argument value for a specific function context
        @param function_context: function_context object to retrieve return arg values from
        @return:
        """

        if function_context is None:
            return None

        if function_context.ret_arg_value is None:
            return None

        return self.dbg_values[function_context.ret_arg_value]


    def get_function_arg(self, function, arg_index):
        """
        Get a function argument object at specific index
        @param function: The function to retrieve the argument for
        @param arg_index: the argument index
        @return:
        """
        if arg_index == -1:
            arg_id = function.ret_arg
            if arg_id is None:
                return None
        else:
            arg_id = function.args[arg_index]
            if arg_id is None:
                return None

        return self.function_args[arg_id]

    def get_parsed_values(self, dbg_value=None):
        """
        Get parsed value list
        @param dbg_value: a debug value object to retrieve parsed values from. (type: dbDebug_Values)
        @return:
        """
        parsed_val_list = []

        if dbg_value is not None:
            parsed_val_id_list = dbg_value.parsed_values
        else:
            parsed_val_id_list = self.parsed_values

        return [self.parsed_values[parsed_val_id] for parsed_val_id in parsed_val_id_list]


    def get_dbg_value(self, dbg_val_id):
        """
        Get debug value from debug_val_id
        @param dbg_val_id: debug value id
        @return: a debug value object
        """
        if dbg_val_id is not None:
            return self.dbg_values[dbg_val_id]

        return None

    def count_function_occurs(self, function, thread_id=None):
        """
        Count run-time function occurrences
        @param function: Count occurrences for this function only
        @param thread_id: Count occurrences matching this thread_id only.
        @return: Number of run-time occurrences for the function
        """
        if function is None:
            return 0

        if not isinstance(function, dbFunction):
            raise ValueError("dbFunction type is expected. Got %s." % function.__class__)

        if thread_id is None:
            return len(function.function_contexts)

        count = 0
        for func_context in self.get_function_context_list(function):
            if func_context.thread_id == thread_id:
                count += 1

        return count

    def get_best_parsed_val(self, parsed_vals):
        """
        Gets the best parsed value from a prased value list
        @param parsed_vals: parsed value list
        @return: A tuple of ( (bool)isGussed, (dbParsed_Value)best_value )
        """

        if parsed_vals is None or len(parsed_vals) == 0:
            return None

        best_val = min(parsed_vals, key=operator.attrgetter("score"))

        if best_val.score == 0:
            return False, best_val

        return True, best_val

    def get_all_values(self):
        """
        Get all parsed values from the db
        @return: A list of parsed values (of type dbParsed_Value)
        """
        return self.parsed_values.values()


    def get_all_values_dict(self):
        """
        Get all parsed value from the db as a dictionary with value.type as key
        @return: a dictionary with value.type as key and a list of parsed values as value
        """

        value_dict = {}

        for cur_val in self.parsed_values.values():
            if cur_val.type in value_dict:
                value_dict[cur_val.type].append(cur_val)
            else:
                value_dict[cur_val.type] = [cur_val]

        return value_dict

    def get_all_value_types(self):
        """
        Get all contained value types
        @return: a list of all of the contained value types
        """

        return list(set(self.parsed_values.values()))

    def get_parsed_value_contexts(self, value):
        """
        Get the ea`s of a parsed value item
        @return: address list of function context items containing the value calls
        """

        if not isinstance(value, dbParsed_Value):
            raise TypeError("Expected type dbParsed_Value but got type: %s" % value.__class__)

        func_context_list = []

        for dbg_val_id in value.dbgValues:
            dbg_val = self.get_dbg_value(dbg_val_id)

            if dbg_val.function_context is not None:
                func_context = self.get_function_context(dbg_val.function_context)
                func_context_list.append(func_context)

        return func_context_list

    def get_thread_list(self):
        """
        Get a list of threads from DB
        @return: a list of thread objects (of type dbThread)
        """
        return self.threads.values()


    def get_run_info(self):
        """
        Get run information
        @return: a tuple of (comment, start_time, end_time, analyzed_filename,
                             num_of_exec_function, num_of_threads, num_of_parsed_vals)
        """

        num_of_exec_funcs = len(self.functions)
        num_of_threads = len(self.threads)
        num_of_parsed_vals = len(self.parsed_values)

        RunInfo = namedtuple("RunInfo", "start end filename num_of_functions num_of_threads num_of_values")

        return RunInfo(self.run_info.start_time,
                       self.run_info.end_time,
                       self.run_info.file,
                       num_of_exec_funcs,
                       num_of_threads,
                       num_of_parsed_vals)

    #############################################################################
    # DB Utils

    def get_function_counter(self):
        """
        Get a Counter object representing the program executed function count
        @return: Counter object with function_start_address as the key value
        """
        func_counter = Counter()
        for func_context in self.get_function_context_list():
            if func_context.function is not None:
                func_counter[self.functions[func_context.function].function_start] += 1

        return func_counter


    def get_call_graph_to(self, function_context=None):
        """
        Get a execution call graph leading to a function.
        @param function_context: dbFunction_Context to start the call-graph from
        @return: A tuple array, where each tuple represents (FromAdr, ToAdr), e.g: (Calee_Func_EA , Called Func_EA)
        """
        cur_context = function_context
        call_graph_list = []
        prev_func_ea = None
        cur_func_ea = None

        if cur_context is None:
            return call_graph_list

        while True:
            if cur_context.parent_func_ctxt_id in self.function_contexts:
                prev_context = self.function_contexts[cur_context.parent_func_ctxt_id]
                if prev_context.function is not None and prev_context.function in self.functions:
                    prev_func_ea = self.functions[prev_context.function].function_start
                if cur_context.function is not None and cur_context.function in self.functions:
                    cur_func_ea = self.functions[cur_context.function].function_start

                if prev_func_ea and cur_func_ea:
                    call_graph_list.append((prev_func_ea, cur_func_ea))

                cur_context = prev_context
            else:
                break

        return call_graph_list

    def get_call_graph_from(self, function_context=None):
        """
        Get a execution call graph from a function
        @param function_context: dbFunction_Context to start the call-graph from
        @return: A tuple array, where each tuple represents (FromAdr, ToAdr), e.g: (Calee_Func_EA , Called Func_EA)
        """
        cur_context = function_context
        call_graph_list = []
        prev_func_ea = None
        next_func_ea = None

        if cur_context is None:
            return call_graph_list

        if cur_context.function in self.functions:
            prev_func_ea = self.functions[cur_context.function].function_start

        for next_func_ctxt_id in cur_context.child_func_ctxt_id_list:
            if next_func_ctxt_id not in self.function_contexts:
                continue

            next_context = self.function_contexts[next_func_ctxt_id]

            if next_context.function in self.functions:
                next_func_ea = self.functions[next_context.function].function_start

            if prev_func_ea and next_func_ea:
                call_graph_list.append((prev_func_ea, next_func_ea))

            call_graph_list += self.get_call_graph_from(next_context)

        return call_graph_list

    def get_call_graph_complete(self):
        """
        Get an execution call graph for the entire execution
        @return: A tuple array, where each tuple represents (FromAdr, ToAdr), e.g: (Calee_Func_EA , Called Func_EA)
        """
        call_graph_list = []
        prev_func_ea = None
        next_func_ea = None

        for cur_context_id in self.function_contexts:
            cur_context = self.function_contexts[cur_context_id]
            if cur_context.function in self.functions:
                prev_func_ea = self.functions[cur_context.function].function_start

            for next_context_id in cur_context.child_func_ctxt_id_list:
                if next_context_id in self.function_contexts:
                    next_context = self.function_contexts[next_context_id]

                    if next_context.function in self.functions:
                        next_func_ea = self.functions[next_context.function].function_start

                if prev_func_ea and next_func_ea:
                    call_graph_list.append((prev_func_ea, next_func_ea))

        return call_graph_list

    #############################################################################
    # Add data base items
    #############################################################################

    def add_run_info(self, call_stack, start_time, end_time, debugged_file, md5):
        """
        Add runtime info to DB
        @param start_time: Debugging start time
        @param end_time: Debugging end time
        @param debugged_file: Analyzed file name
        @param call_stack: a dictionary where Key = ThreadID , Value = call_tree
        @return:
        """
        try:
            self.run_info = dbRun_Info(start_time, end_time, debugged_file, md5)

            for thread_id in call_stack:
                thread_id = self.add_thread_data(thread_id, call_stack[thread_id].callTree)
                self.run_info.threads.append(thread_id)

            self.is_saved = False  # Un-check the saved flag
            return True

        except Exception as ex:
            self.logger.exception("Error while loading RunInfo data into DieDB: %s", ex)

    def add_thread_data(self, thread_num, call_tree):
        """
        Add a new thread data to DIE database
        @param thread_num: Thread number
        @param call_tree: call_tree (List of FunctionContext objects).
        @return:
        """

        try:
            cur_thread = dbThread(thread_num)
            thread_id = id(cur_thread)

            for function_context in call_tree:
                func_context_id = self.add_function_context(function_context, cur_thread.thread_num)
                cur_thread.cfg.append(func_context_id)

            self.threads[thread_id] = cur_thread

            self.is_saved = False  # Un-check the saved flag
            return thread_id

        except Exception as ex:
            self.logger.exception("Error while loading thread-%d to DieDB: %s", thread_num, ex)

    def add_function_context(self, function_context, thread_id):
        """
        Add function context data to the DB
        @param function_context: object of type FunctionContext
        @return:
        """
        try:
            parent_func_context_id = None
            if function_context.parent_func_context is not None:
                parent_func_context_id = function_context.parent_func_context.id

            cur_func_context = dbFunction_Context(function_context.id,
                                                  function_context.callRegState,
                                                  function_context.retRegState,
                                                  function_context.callingEA,
                                                  parent_func_context_id,
                                                  function_context.is_indirect,
                                                  function_context.is_new_func,
                                                  function_context.calling_function_name,
                                                  function_context.total_proc_time,
                                                  thread_id)
            if not function_context.empty:

                for func_ctxt in function_context.child_func_context:
                    cur_func_context.child_func_ctxt_id_list.append(func_ctxt.id)

                cur_func_context.function = self.add_function(function_context.function, function_context.id)

                for call_value in function_context.callValues:
                    dbg_val_id = self.add_debug_value(call_value, function_context.id)
                    cur_func_context.call_values.append(dbg_val_id)

                for ret_value in function_context.retValues:
                    dbg_val_id = self.add_debug_value(ret_value, function_context.id)
                    cur_func_context.ret_values.append(dbg_val_id)

                # If return argument exist, add its value to DB.
                if function_context.retArgValue is not None:
                    dbg_val_id = self.add_debug_value(function_context.retArgValue, function_context.id)
                    cur_func_context.ret_arg_value = dbg_val_id

            self.function_contexts[function_context.id] = cur_func_context

            self.is_saved = False  # Un-check the saved flag
            return function_context.id

        except Exception as ex:
            self.logger.exception("Error while adding function %s to DieDB: %s", function_context.function.funcName, ex)

    def add_function(self, function, func_context_id):
        """
        Add function data to DB
        @param function: object of type Function
        @param function_context: the calling dbFunction_Context object
        @return:
        """

        try:
            cur_function = dbFunction(function.funcName, function.func_start, function.func_end, function.proto_ea,
                                      function.argNum, function.isLibFunc, function.library_name)
            func_id = cur_function.__hash__()

            if func_id in self.functions:
                self.functions[func_id].function_contexts.append(func_context_id)
                return func_id

            cur_function.function_contexts.append(func_context_id)

            for func_arg in function.args:
                arg_id = self.add_func_arg(func_arg)
                cur_function.args.append(arg_id)

            # If return argument exist, add it to db.
            if function.retArg is not None:
                ret_arg_id = self.add_func_arg(function.retArg)
                cur_function.ret_arg = ret_arg_id

            self.functions[func_id] = cur_function

            self.is_saved = False  # Un-check the saved flag
            return func_id

        except Exception as ex:
            self.logger.exception("Error while loading function %s into DieDB: %s", function.funcName ,ex)

    def add_func_arg(self, func_arg):
        """
        Function Argument Data
        @param func_arg: object of type FuncArg
        @return:
        """

        try:
            cur_arg = dbFuncArg(func_arg.argname, func_arg.type_str(), func_arg.argNum, func_arg.isStack())
            arg_id = id(cur_arg)
            self.function_args[arg_id] = cur_arg

            self.is_saved = False  # Un-check the saved flag
            return arg_id

        except Exception as ex:
            self.logger.exception("Error while loading function argument %s into DieDB: %s", func_arg.argname, ex)

    def add_debug_value(self, debug_value, func_context_id, ref_blink_id=None):
        """
        Add debug value to the DB
        @param debug_value: object of type DebugValue
        @param func_context_id: The containing function context id
        @param ref_blink_id: id of the referring dbDebugValue object
        @return:
        """
        try:
            cur_dbg_value = dbDebug_Values(debug_value.rawValue,
                                           debug_value.typeName(),
                                           debug_value.name,
                                           debug_value.is_definitely_parsed(),
                                           debug_value.derefrence_depth)
            dbg_val_id = id(cur_dbg_value)

            cur_dbg_value.function_context = func_context_id

            # TODO: Check against None type was added as a quick fix, Check why is this needed here.
            if debug_value.parsedValues is not None:
                for parsed_val in debug_value.parsedValues:
                    parsed_val_id = self.add_parsed_val(parsed_val)
                    cur_dbg_value.parsed_values.append(parsed_val_id)
                    self.parsed_values[parsed_val_id].dbgValues.append(dbg_val_id)

            for nested_val in debug_value.nestedValues:
                nested_dbg_val_id = self.add_debug_value(nested_val, func_context_id)
                cur_dbg_value.nested_values.append(nested_dbg_val_id)

            if ref_blink_id is not None:
                cur_dbg_value.reference_blink = ref_blink_id

            if debug_value.reference_flink is not None:
                ref_flink_id = self.add_debug_value(debug_value.reference_flink, func_context_id=func_context_id,
                                                    ref_blink_id=dbg_val_id)
                cur_dbg_value.reference_flink = ref_flink_id

            # Get the best parsed value (lowest score)
            best_score = 10
            for parsed_val_id in cur_dbg_value.parsed_values:
                cur_parsed_val = self.parsed_values[parsed_val_id]
                if cur_parsed_val.score <= best_score:
                    cur_dbg_value.best_val_id = parsed_val_id
                    best_score = cur_parsed_val.score

            self.dbg_values[dbg_val_id] = cur_dbg_value

            self.is_saved = False  # Un-check the saved flag
            return dbg_val_id

        except Exception as ex:
            self.logger.exception("Error while loading DebugValue to DieDB: %s", ex)

    def add_parsed_val(self, parsed_val):
        """
        Add dynamically parsed value
        @param parsed_val: object of type ParsedValue
        @return:
        """
        try:
            cur_parsed_val = dbParsed_Value(parsed_val.data, parsed_val.description, parsed_val.raw, parsed_val.score,
                                            parsed_val.type)
            parsed_val_id = cur_parsed_val.__hash__()

            if not parsed_val_id in self.parsed_values:
                self.parsed_values[parsed_val_id] = cur_parsed_val

            self.is_saved = False  # Un-check the saved flag
            return parsed_val_id

        except Exception as ex:
            self.logger.exception("Error while loading parsed data into DieDB: %s", ex)


####################################################################################
# Serialization

    def get_default_db_filename(self):
        """
        Get the default DIE DB filename
        """
        filename, extension = os.path.splitext(idaapi.get_input_file_path())
        return filename + ".ddb"

    def save_db(self, file_name=None):
        """
        Seralize DB and save to file
        @param file_name: DB filename
        @return: True on success otherwise False
        """
        try:

            if self.is_saved:
                self.logger.info("DB was not saved - no data to save")
                return

            if file_name is None:
                file_name = self.get_default_db_filename()

            out_file = open(file_name, 'wb')

            db_tables = [self.run_info,
                         self.functions,
                         self.function_args,
                         self.function_contexts,
                         self.threads,
                         self.dbg_values,
                         self.parsed_values,
                         self.excluded_bp_ea,
                         self.excluded_funcNames_part,
                         self.excluded_funcNames,
                         self.excluded_modules
            ]

            pickle.dump(db_tables, out_file)

            self.is_saved = True  # Check the saved flag
            return True

        except Exception as ex:
            idaapi.msg("Error while saving DIE DB: %s\n" % ex)
            logging.exception("Error while saving DIE DB: %s", ex)
            return False

    def load_db(self, file_name=None):
        """
        Load DB from file and DeSeralize
        @param file_name: DB filename
        @return: True on success otherwise False
        """
        if file_name is None:
            file_name = self.get_default_db_filename()

        if not os.path.exists(file_name):
            raise IOError("DIE DB file not found")

        in_file = open(file_name, 'rb')

        db_tables = pickle.load(in_file)

        # Validate db MD5
        db_md5 = db_tables[0].md5
        if db_md5 != idautils.GetInputFileMD5():
            raise DbFileMismatch("Db File is different then currently analyzed file")

        self.run_info = db_tables[0]
        self.functions = db_tables[1]
        self.function_args = db_tables[2]
        self.function_contexts = db_tables[3]
        self.threads = db_tables[4]
        self.dbg_values = db_tables[5]
        self.parsed_values = db_tables[6]
        self.excluded_bp_ea = db_tables[7]
        self.excluded_funcNames_part = db_tables[8]
        self.excluded_funcNames = db_tables[9]
        self.excluded_modules = db_tables[10]

        return True


#############################################################################
# Singleton
#############################################################################

__die_db = DIE_DB()

def initialize_db():
    global __die_db
    __die_db = DIE_DB()

def get_db():
    return __die_db