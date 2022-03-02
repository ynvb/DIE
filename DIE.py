import networkx as nx
from awesome.context import ignored
import sark
import sark.qt
from sark.qt import QtGui, QtCore
import logging
import logging.handlers as handlers

import os
from time import ctime

from idaapi import plugin_t
import idaapi
import idautils
import idc
import sark.ui


from DIE.Lib.IDAConnector import *
import DIE.Lib.DieConfig
import DIE.Lib.DIEDb
from DIE.Lib import DebugAPI

#import DIE.UI.BPView
import DIE.UI.FunctionViewEx
import DIE.UI.ValueViewEx
import DIE.UI.ParserView
import DIE.UI.BPView
import DIE.UI.SetupView
import DIE.UI.Die_Icons
from DIE.UI.FuncScopeChooser import ScopeChooser
from DIE.UI.AboutScreen import AboutWindow

from DIE.Lib.DIE_Exceptions import DbFileMismatch

class MenuHelperException(Exception):
    pass

  
class DieManager:
    """
    Manage the DIE framework
    """

    def __init__(self, is_dbg_log=True, is_dbg_pause=False, is_dbg_profile=False):
        ### Logging ###

        log_filename = os.path.join(os.getcwd(), "DIE.log")

        self._menus_names = []

        #TODO: Fix logging to include rotating_file_handler \ console_logging
        if is_dbg_log:
            logging.basicConfig(filename=log_filename,
                        level=logging.DEBUG,
                        format='[%(asctime)s] [%(levelname)s] [%(name)s][%(filename)s:%(lineno)s] : %(message)s')
        else:
             logging.basicConfig(filename=log_filename,
                    level=logging.INFO,
                    format='[%(asctime)s] [%(levelname)s] [%(name)s][%(filename)s:%(lineno)s] : %(message)s')

        idaapi.msg("Log file created at %s\n" % log_filename)
        self.logger = logging.getLogger(__name__)

        ### DIE Configuration ###
        self.config_file_name = os.path.join(os.getcwd(), "DIE.cfg")
        DIE.Lib.DieConfig.initialize()
        config = DIE.Lib.DieConfig.get_config()
        try:
            config.load(self.config_file_name)
        except IOError:
            pass

        except:
            import traceback
            idaapi.msg(traceback.format_exc())

        self.die_config = config

        self.icon_list = {}

        self.debugAPI = DebugAPI.DebugHooker(is_dbg_pause, is_dbg_profile)
        DIE.Lib.DIEDb.initialize_db()
        self.die_db = DIE.Lib.DIEDb.get_db()

        self.is_marked = False

        DIE.UI.FunctionViewEx.initialize()
        DIE.UI.ValueViewEx.initialize()
        DIE.UI.BPView.initialize()
        DIE.UI.ParserView.initialize()
        DIE.UI.Die_Icons.initlialize()
        self.function_view = DIE.UI.FunctionViewEx.get_view()
        self.value_view = DIE.UI.ValueViewEx.get_view()
        self.bp_view = DIE.UI.BPView.get_view()
        self.parser_view = DIE.UI.ParserView.get_view()

        self.load_icons()

        return

    ###########################################################################
    # Icons

    def load_icon(self, icon_filename, icon_key_name):
        """
        Load a single custom icon
        @param icon_filename: Icon file name
        @param icon_key_name: The key value to store the icon with in the icon_list.
        """
        try:
            icons_path = self.die_config.icons_path

            icon_filename = os.path.join(icons_path, icon_filename)
            icon_num = idaapi.load_custom_icon(icon_filename)
            self.icon_list[icon_key_name.lower()] = icon_num
            return True

        except Exception as ex:
            self.logger.error("Failed to load icon %s: %s", icon_filename, ex)
            return False

    def load_icons(self):
        """
        Load custom DIE Icons
        """
        self.load_icon("dbg.png", "debug")
        self.load_icon("dbg_all.png", "debug_all")
        self.load_icon("dbg_custom.png", "debug_scope")
        self.load_icon("die.png", "die")
        self.load_icon("funcview.png", "function_view")
        self.load_icon("valueview.png", "value_view")
        self.load_icon("stop.png", "exception_view")
        self.load_icon("settings.png", "settings")
        self.load_icon("plugins.png", "plugins")
        self.load_icon("save.png", "save")
        self.load_icon("load.png", "load")


    ###########################################################################
    # Menu Items

    # Handlers
    class DIE_gohere_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
             idaapi.action_handler_t.__init__(self)
             self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.go_here()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class DIE_goall_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
            idaapi.action_handler_t.__init__(self)
            self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.go_all()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class DIE_goscope_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
            idaapi.action_handler_t.__init__(self)
            self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.show_scope_chooser()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class DIE_show_funcview_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
            idaapi.action_handler_t.__init__(self)
            self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.show_function_view()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class DIE_show_valview_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
            idaapi.action_handler_t.__init__(self)
            self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.show_value_view()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class DIE_show_parsersview_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
            idaapi.action_handler_t.__init__(self)
            self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.show_parser_view()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class DIE_show_exceptionsview_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
            idaapi.action_handler_t.__init__(self)
            self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.show_breakpoint_view()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class DIE_load_db_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
            idaapi.action_handler_t.__init__(self)
            self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.load_db()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class DIE_save_db_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
            idaapi.action_handler_t.__init__(self)
            self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.save_db()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class DIE_show_cfg_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
            idaapi.action_handler_t.__init__(self)
            self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.show_cfg()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class DIE_mark_execflow_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
            idaapi.action_handler_t.__init__(self)
            self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.mark_exec_flow()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class DIE_show_about_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
            idaapi.action_handler_t.__init__(self)
            self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.show_about()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class DIE_show_settings_Handler(idaapi.action_handler_t):
        def __init__(self, outer_instance):
            idaapi.action_handler_t.__init__(self)
            self.outer_instance = outer_instance

        def activate(self, ctx):
            self.outer_instance.show_settings()
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


    def add_menu_item_helper(self, name, text, tooltip, handler, icon, shortcut):
        description = idaapi.action_desc_t(name, text, handler, shortcut, tooltip, icon)
        idaapi.register_action(description)
        idaapi.attach_action_to_menu("DIE/" + text, name, idaapi.SETMENU_APP)

        self._menus_names.append(name)


    def add_menu_items(self):
        # Add root level menu
        idaapi.create_menu('DIE', 'DIE')

        # Save DieDB
        self.add_menu_item_helper( 'DIE:savedb',  '&Save DieDB', 'Saves DieDB',
                                   self.DIE_save_db_Handler(self),  self.icon_list['save'], '')

        # Load DieDB
        self.add_menu_item_helper( 'DIE:loaddb',  '&Load DieDB', 'Loads DieDB',
                                   self.DIE_load_db_Handler(self),  self.icon_list['load'], '')

        # Show complete execution CFG
        self.add_menu_item_helper( 'DIE:showcfg', 'Show &CFG',  'Shows control flow graph',
                                   self.DIE_show_cfg_Handler(self),  -1                   , '')

        # Mark\Unmark Execution Flow
        self.add_menu_item_helper( 'DIE:markexecutionflow', r'Mark\&Unmark Execution flow',
                                   r'DIE Mark\Unmark Execution flow', 
                                   self.DIE_mark_execflow_Handler(self), -1, '')

        # Parser View
        self.add_menu_item_helper( 'DIE:parsersview', '&Parsers view',  'DIE Parsers view',
                                   self.DIE_show_parsersview_Handler(self),   self.icon_list['plugins'], '')

        # Exceptions View
        self.add_menu_item_helper( 'DIE:exceptionsview', 'E&xceptions view',  'DIE Exceptions view',
                                   self.DIE_show_exceptionsview_Handler(self), self.icon_list['exception_view'], '')

        # Value View
        self.add_menu_item_helper( 'DIE:valueview', '&Value view', 'DIE Value view',
                                   self.DIE_show_valview_Handler(self), self.icon_list['value_view'], '')

        # Function View
        self.add_menu_item_helper( 'DIE:functionview', '&Function view', 'DIE Function view',
                                   self.DIE_show_funcview_Handler(self), self.icon_list['function_view'], '')

        # Debug a custom scope
        self.add_menu_item_helper( 'DIE:debugcustomscope', 'Debug a c&ustom scope', 'DIE Debug a custom scope',
                                   self.DIE_goscope_Handler(self), self.icon_list['debug_scope'], 'Ctrl+Alt+c')

        # Debug entire code
        self.add_menu_item_helper( 'DIE:debugentirecode', 'Debug &entire code', 'DIE Debug entire code',
                                   self.DIE_goall_Handler(self), self.icon_list['debug_scope'], 'Ctrl+Alt+g')

        # Debug from current location
        self.add_menu_item_helper( 'DIE:gofromcurrentlocation', '&Debug from current location', 'DIE from current location',
                                   self.DIE_gohere_Handler(self), self.icon_list['debug'], 'Ctrl+Alt+f')

        # Settings
        self.add_menu_item_helper( 'DIE:settings', 'Se&ttings', 'DIE Settings',
                                   self.DIE_show_settings_Handler(self), self.icon_list['settings'], '')

        # About
        self.add_menu_item_helper( 'DIE:about', 'About', 'DIE About',
                                   self.DIE_show_about_Handler(self), -1, '')


    def del_menu_items(self):
        for menu_name in self._menus_names:
            idaapi.unregister_action(menu_name)
        idaapi.delete_menu('DIE')


    ###########################################################################
    # Debugging
    def go_here(self):
        self.debugAPI.start_debug(idc.here(), None, auto_start=True)

    def go_all(self):
        self.debugAPI.start_debug(None, None, auto_start=True)

    def show_scope_chooser(self):
        global chooser

        functions = get_functions()
        func_list = functions.keys()

        chooser = ScopeChooser(func_list)
        chooser.Compile()

        ok = chooser.Execute()
        if ok == 1:
            start_func = func_list[chooser.cbStartFunction.value]
            start_func_ea = functions[start_func]

            end_func = func_list[chooser.cbEndFunction.value]
            end_func_ea = functions[end_func]

            self.debugAPI.start_debug(start_func_ea, end_func_ea, True)

        chooser.Free()

    ###########################################################################
    # DIE DB
    def save_db(self):
        db_file = idc.AskFile(1, "*.ddb", "Save DIE Db File")
        if db_file is None:
            return

        self.die_db.save_db(db_file)

    def load_db(self):
        try:
            db_file = idc.AskFile(0, "*.ddb", "Load DIE Db File")
            if db_file is not None:
                self.die_db.load_db(db_file)

            if self.die_db is not None:
                self.show_db_details()

        except DbFileMismatch as mismatch:
            idaapi.msg("Error while loading DIE DB: %s\n" % mismatch)

        except Exception as ex:
            logging.exception("Error while loading DB: %s", ex)
            return False


    ###########################################################################
    # Function View
    def show_function_view(self):
        self.function_view.Show()

    ###########################################################################
    # Value View
    def show_value_view(self):
        self.value_view.Show()

    ###########################################################################
    # Parser View
    def show_parser_view(self):
        self.parser_view.Show()

    ###########################################################################
    # Exceptions View
    def show_breakpoint_view(self):
        self.bp_view.Show()

    ###########################################################################
    # About
    def show_about(self):
        AboutWindow().exec_()

    ###########################################################################
    # Settings View
    def show_settings(self):
        DIE.UI.SetupView.Show(self.config_file_name)

    ###########################################################################
    # Show DB Details

    def show_db_details(self):
        """
        Print DB details
        """
        (start_time,
         end_time,
         filename,
         num_of_functions,
         num_of_threads,
         numof_parsed_val) = self.die_db.get_run_info()

        idaapi.msg("Die DB Loaded.\n")
        idaapi.msg("Start Time: %s, End Time %s\n" % (ctime(start_time), ctime(end_time)))
        idaapi.msg("Functions: %d, Threads: %d\n" % (num_of_functions, num_of_threads))
        idaapi.msg("Parsed Values: %d\n" % numof_parsed_val)

    ###########################################################################
    # Mark\Unmark Execution Flow

    def mark_exec_flow(self):
        """
        Mark \ Unmark execution flow
        """
        color = 0x123456
        if self.is_marked:
            color = None

        with sark.ui.Update():
            for func_ea in self.die_db.get_function_counter():
                try:
                    sark.Function(func_ea).color = color
                except sark.exceptions.SarkNoFunction:
                    pass

        # Swap is_marked value
        self.is_marked = not self.is_marked

    ###########################################################################
    # Show CFG

    def show_cfg(self):
        """
        Show execution Call flow graph
        """
        cfg = self.die_db.get_call_graph_complete()
        graph = nx.DiGraph()

        if not cfg:
            idaapi.msg("No CFG to display")
            return

        for ctxt_node in cfg:
            (from_address, to_address) = ctxt_node
            graph.add_edge(from_address, to_address)

        viewer = sark.ui.NXGraph(graph, "Call graph for execution CFG", handler=sark.ui.AddressNodeHandler())
        viewer.Show()

    def show_logo(self):
        """
        Show DIE Logo
        """
        idaapi.msg('-----------------------------------------------------\n'
                   '                           _________-----_____       \n'
                   '        _____------           __      ----_          \n'
                   ' ___----             ___------             /\        \n'
                   '    ----________        ----                 \       \n'
                   '                -----__    |             _____)      \n'
                   '                     __-                /    /\      \n'
                   '         _______-----    ___--          \    /)\     \n'
                   '   ------_______      ---____            \__/  /     \n'
                   '                -----__    \ --    _          //\    \n'
                   '                       --__--__     \_____/   \_/\   \n'
                   '                               ----|   /          |  \n'
                   ' Dynamic                           |  |___________|  \n'
                   ' IDA                               |  | ((_(_)| )_)  \n'
                   ' Enrichment                        |  \_((_(_)|/(_)  \n'
                   '                                   \             (   \n'
                   '                                    \_____________)  \n'
                   ' D.I.E v0.1 is now loaded, enjoy.                    \n'
                   '-----------------------------------------------------\n'
                   )


class die_plugin_t(plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Dynamic IDA Enrichment plugin (aka. DIE)"
    help = "Help is a matter of trust."
    wanted_name = "DIE"
    wanted_hotkey = ""

    def init(self):
        try:
            # For Debugging:
            #self.die_manager = DieManager(is_dbg_log=True, is_dbg_pause=False, is_dbg_profile=True)
            self.die_manager = DieManager()
            self.die_manager.add_menu_items()
            self.die_manager.show_logo()
            return idaapi.PLUGIN_KEEP

        except Exception as ex:
            idaapi.msg("Failed to initialize DIE. {}\n".format(ex))
            self.die_manager.del_menu_items()
            del self.die_manager
            idaapi.msg("Errors and fun!\n")
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        with ignored(AttributeError):
            if not self.die_manager.die_db.is_saved:
                response = idc.AskYN(1, "DIE DB was not saved, Would you like to save it now?")
                if response == 1:
                    self.die_manager.save_db()

            self.die_manager.del_menu_items()


def PLUGIN_ENTRY():
    return die_plugin_t()

