from idaapi import Form
import DIE.Lib.DieConfig


class SettingsView(Form):
    def __init__(self):
        Form.__init__(self, ("STARTITEM 0\n"
                             "BUTTON YES* Save Settings\n"
                             "BUTTON CANCEL Cancel\n"
                             "Form Setup View\n"
                             "\n"
                             "Debbuging:\n"
                             "<##Maximal function calls:{iMaxFuncCall}>\n"
                             "<##Maximal dereference depth:{iDerefDepth}>\n"
                             "\n"
                             "\n"
                             "Debug Values:\n"
                             "<Step Into System Libraries:{rStepInSysLibs}>\n"
                             "<New Function Analysis:{rFuncAnalysis}>\n"
                             "<Add xrefs:{rAddXref}>\n"
                             "<Raw:{rRaw}>\n"
                             "<Parse:{rParse}>\n"
                             "<Array:{rArray}>\n"
                             "<Enum:{rEnum}>\n"
                             "<Containers:{rContainer}>\n"
                             "<Dereference:{rDeref}>\n"
                             "<Arguments:{rArgs}>{cDebugValues}>\n"
                             "\n"
                             ), {
                          'cDebugValues': Form.ChkGroupControl(
                              ("rStepInSysLibs", "rAddXref", "rFuncAnalysis", "rRaw", "rParse", "rArray", "rContainer",
                               "rDeref", "rArgs", "rEnum")),
                          'iMaxFuncCall': Form.NumericInput(tp=Form.FT_DEC),
                          'iDerefDepth': Form.NumericInput(tp=Form.FT_DEC),
                      })

    def OnButtonNop(self, code=0):
        """Do nothing, we will handle events in the form callback"""
        pass


def Show(config_filename):
    die_config = DIE.Lib.DieConfig.get_config()

    settings = SettingsView()
    settings.Compile()

    settings.iMaxFuncCall.value = die_config.debugging.max_func_call
    settings.iDerefDepth.value = die_config.debugging.max_deref_depth

    settings.rDeref.checked = die_config.debug_values.is_deref
    settings.rRaw.checked = die_config.debug_values.is_raw
    settings.rEnum.checked = die_config.debug_values.is_enum
    settings.rParse.checked = die_config.debug_values.is_parse
    settings.rArray.checked = die_config.debug_values.is_array
    settings.rContainer.checked = die_config.debug_values.is_container
    settings.rFuncAnalysis.checked = die_config.function_context.new_func_analysis
    settings.rAddXref.checked = die_config.function_context.add_xref
    settings.rStepInSysLibs.checked = die_config.debugging.step_into_syslibs

    settings.rArgs.checked = die_config.function_context.get_func_args

    ok = settings.Execute()
    if ok == 1:
        die_config.debugging.max_deref_depth = settings.iDerefDepth.value
        die_config.debugging.max_func_call = settings.iMaxFuncCall.value

        die_config.debug_values.is_deref = settings.rDeref.checked
        die_config.debug_values.is_enum = settings.rEnum.checked
        die_config.debug_values.is_raw = settings.rRaw.checked
        die_config.debug_values.is_parse = settings.rParse.checked
        die_config.debug_values.is_array = settings.rArray.checked
        die_config.debug_values.is_container = settings.rContainer.checked
        die_config.function_context.new_func_analysis = settings.rFuncAnalysis.checked
        die_config.function_context.add_xref = settings.rAddXref.checked
        die_config.debugging.step_into_syslibs = settings.rStepInSysLibs.checked

        die_config.function_context.get_func_args = settings.rArgs.checked

        print settings.iMaxFuncCall.value
        print settings.iDerefDepth.value

        die_config.save(config_filename)
