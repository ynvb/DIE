import sark
from DIE.Lib import DIEDb

db = DIEDb.get_db()  # A global DIE database instance


def does_return_string(function):
    """
    Check if a function returns a string.
    @param function: db_DataTypes.dbFunction object
    @return: True if the function return value contains a string
    """
    for ctx in function.function_contexts:
        ret_val = db.get_dbg_value(db.get_function_context(ctx).ret_arg_value)
        parsed_values = db.get_parsed_values(ret_val)
        if parsed_values:
            for value in parsed_values:
                if value.type == "basicstring":
                    return True
    return False


def get_all_functions_returning_strings(functions):
    """
    Get all functions with string in return values
    @param functions: List of db_DataTypes.dbFunction objects
    @return: a list of db_DataTypes.dbFunction objects containing strings in return value
    """
    fs = []
    for f in functions:
        if does_return_string(f):
            fs.append(f)
    return fs


def get_most_called_n(functions, n):
    """
    Get the n`th most called functions
    @param functions: List of db_DataTypes.dbFunction objects
    @param n: Sum of returned functions
    @return: a list of the top n`th called db_DataTypes.dbFunction objects
    """
    call_counts = ((function, len(function.function_contexts)) for function in functions)
    sorted_funcs = sorted(call_counts, key=lambda x: x[1], reverse=True)
    return [count[0] for count in sorted_funcs[:n]]


def get_non_lib(functions):
    """
    Get all non-library functions
    @param functions: List of db_DataTypes.dbFunction objects
    @return: a subset list of db_DataTypes.dbFunction objects that are not library functions.
    """
    return [f for f in functions if not f.is_lib_func]


def sort_by_xrefs(functions):
    """
    Sort by the number of Xrefs to the fucntion
    @param functions: List of db_DataTypes.dbFunction objects
    @return: a sorted list of db_DataTypes.dbFunction objects by Xref count.
    """
    xref_counts = []
    for f in functions:
        try:
            xref_counts.append((f, (len(list(sark.Function(ea=f.function_start).xrefs_to)))))
        except sark.exceptions.SarkNoFunction:
            pass
    sorted_funcs = sorted(xref_counts, key=lambda x: x[1], reverse=True)
    return [count[0] for count in sorted_funcs]



# no_lib_funcs = get_non_lib(functions)
# funcs_returning_strings = get_all_functions_returning_strings(no_lib_funcs)
# most_called_funcs = get_most_called_n(funcs_returning_strings, 10)
# sorted_funcs = sort_by_xrefs(most_called_funcs)
#
#
# for f in sorted_funcs:
#     print f.function_name, len(list(sark.Function(ea=f.function_start).xrefs_to))