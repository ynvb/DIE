__author__ = 'yanivb'

from idaapi import Form
import idautils
import idc
from DIE.Lib.IDAConnector import *
from DIE.Lib import DebugAPI

class ScopeChooser(Form):

    def __init__(self, functions):
        self.functions = functions
        Form.__init__(self, (r"STARTITEM 0\n"
                             r"BUTTON YES* StartDIE\n"
                             r"BUTTON CANCEL Cancel\n"
                             r"Form Scope Chooser\n"
                             r"\n"
                             r"<Start Function :{cbStartFunction}>\n"
                             r"<End Function   :{cbEndFunction}>\n"
        ), {
        'iStartAddr' : Form.NumericInput(tp=Form.FT_ADDR),
        'iEndAddr' : Form.NumericInput(tp=Form.FT_ADDR),
        'cbStartFunction': Form.DropdownListControl(
            items=self.functions,
            readonly=True,
            selval=1),
        'cbEndFunction': Form.DropdownListControl(
            items=self.functions,
            readonly=True,
            selval=1),
        })

    def OnButtonNop(self, code=0):
        """Do nothing, we will handle events in the form callback"""
        pass

def __getFunctions():
    """
    Get all current functions
    @return: a tuple of (function_name, function_ea)
    """
    functions = {}
    for func_ea in idautils.Functions():
        functions[get_function_name(func_ea)] = func_ea

    return functions


def Show():
    global chooser
    die_debugger = DebugAPI.DebugHooker()

    functions = __getFunctions()
    func_list = functions.keys()

    chooser = ScopeChooser(func_list)
    chooser.Compile()

    ok = chooser.Execute()
    if ok == 1:
        start_func = func_list[chooser.cbStartFunction.value]
        start_func_ea = functions[start_func]

        end_func = func_list[chooser.cbEndFunction.value]
        end_func_ea = functions[end_func]

        die_debugger.start_debug(start_func_ea, end_func_ea, True)

    chooser.Free()






