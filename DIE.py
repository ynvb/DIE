__author__ = 'yanivb'

import logging
import logging.handlers as handlers

import os
from time import ctime

# This nasty piece of code is here to force the loading of IDA's PySide.
# Without it, Python attempts to load PySide from the site-packages directory,
# and failing, as it does not play nicely with IDA.
import sys
old_path = sys.path[:]
try:
    import idaapi
    ida_python_path = os.path.dirname(idaapi.__file__)
    sys.path.insert(0, ida_python_path)
    from PySide import QtGui, QtCore
finally:
    sys.path = old_path

from idaapi import plugin_t
import idaapi
import idautils
import idc

from DIE.Lib.IDAConnector import *
import DIE.Lib.DieConfig
import DIE.Lib.DIEDb
from DIE.Lib import DebugAPI

import DIE.UI.BPView
import DIE.UI.FunctionViewEx
import DIE.UI.ValueViewEx
import DIE.UI.ParserView
import DIE.UI.BPView
import DIE.UI.SetupView
from DIE.UI.FuncScopeChooser import ScopeChooser
from DIE.UI.AboutScreen import About

from DIE.Lib.DIE_Exceptions import DbFileMismatch


class MenuHelperException(Exception):
    pass


class DieManager():
    """
    Manage the DIE framework
    """

    def __init__(self, is_dbg=False):

        self.is_dbg = is_dbg  # Debug mode flag

        ### Logging ###
        log_filename = os.path.join(os.getcwd(), "DIE.log")
        logging.basicConfig(filename=log_filename,
                            level=logging.INFO,
                            format='[%(asctime)s] [%(levelname)s] [%(name)s] : %(message)s')

        file_handler = handlers.RotatingFileHandler(log_filename, mode='a', maxBytes=100000, backupCount=5)
        console_hanlder = logging.StreamHandler()

        if self.is_dbg:
            file_handler.setLevel(logging.DEBUG)
            console_hanlder.setLevel(logging.DEBUG)
        else:
            file_handler.setLevel(logging.INFO)
            console_hanlder.setLevel(logging.ERROR)

        self.logger = logging.getLogger(__name__)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_hanlder)

        ### DIE Configuration ###
        self.config_file_name = os.path.join(os.getcwd(), "DIE.cfg")
        config = DIE.Lib.DieConfig.get_config()
        config.load_configuration(self.config_file_name)

        self.addmenu_item_ctxs = []
        self.icon_list = {}

        self.debugAPI = DebugAPI.DebugHooker(is_dbg=self.is_dbg)
        self.die_db = DIE.Lib.DIEDb.get_db()
        self.die_config = DIE.Lib.DieConfig.get_config()

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
    def add_menu_item_helper(self, menupath, name, hotkey, pyfunc, flags=1, args=None):

        # add menu item and report on errors
        addmenu_item_ctx = idaapi.add_menu_item(menupath, name, hotkey, flags, pyfunc, args)

        if addmenu_item_ctx is None:
            raise MenuHelperException("Failed adding menu item.")

        self.addmenu_item_ctxs.append(addmenu_item_ctx)

    def add_menu_items(self):
        try:
            # Load DieDB
            self.add_menu_item_helper("Help/About program..", "DIE: Load DieDB", "", self.load_db)
            idaapi.set_menu_item_icon("Help/DIE: Load DieDB", self.icon_list["load"])
            # Save DieDB
            self.add_menu_item_helper("Help/About program..", "DIE: Save DieDB", "", self.save_db)
            idaapi.set_menu_item_icon("Help/DIE: Save DieDB", self.icon_list["save"])
            # Debug Here
            self.add_menu_item_helper("Help/About program..", "DIE: Go from current location", "Alt+f", self.go_here)
            idaapi.set_menu_item_icon("Help/DIE: Go from current location", self.icon_list["debug"])
            # Debug All
            self.add_menu_item_helper("Help/About program..", "DIE: Debug entire code", "Alt+g", self.go_all)
            idaapi.set_menu_item_icon("Help/DIE: Debug entire code", self.icon_list["debug_all"])
            # Debug Custom
            self.add_menu_item_helper("Help/About program..", "DIE: Debug a custom scope", "Alt+c",
                                      self.show_scope_chooser)
            idaapi.set_menu_item_icon("Help/DIE: Debug a custom scope", self.icon_list["debug_scope"])
            # Function View
            self.add_menu_item_helper("Help/About program..", "DIE: Function View", "", self.show_function_view)
            idaapi.set_menu_item_icon("Help/DIE: Function View", self.icon_list["function_view"])
            # Value View
            self.add_menu_item_helper("Help/About program..", "DIE: Value View", "", self.show_value_view)
            idaapi.set_menu_item_icon("Help/DIE: Value View", self.icon_list["value_view"])
            # Exception View
            self.add_menu_item_helper("Help/About program..", "DIE: Exceptions View", "", self.show_breakpoint_view)
            idaapi.set_menu_item_icon("Help/DIE: Exceptions View", self.icon_list["exception_view"])
            # Parsers View
            self.add_menu_item_helper("Help/About program..", "DIE: Parsers View", "", self.show_parser_view)
            idaapi.set_menu_item_icon("Help/DIE: Parsers View", self.icon_list["plugins"])
            # Parsers View
            self.add_menu_item_helper("Help/About program..", "DIE: Settings", "", self.show_settings)
            idaapi.set_menu_item_icon("Help/DIE: Settings", self.icon_list["settings"])
            # About DIE
            self.add_menu_item_helper("Help/About program..", "DIE: About", "", self.show_about)
            idaapi.set_menu_item_icon("Help/DIE: About", self.icon_list["die"])
        except MenuHelperException:
            return 1

        return 0

    def del_menu_items(self):
        for addmenu_item_ctx in self.addmenu_item_ctxs:
            idaapi.del_menu_item(addmenu_item_ctx)

    def doNothing(self):
        """
        Do Nothing
        """
        return

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
    # Parser View
    def show_breakpoint_view(self):
        self.bp_view.Show()

    ###########################################################################
    # About
    def show_about(self):
        about_screen = About()
        ok = about_screen.Execute()
        about_screen.Free()

    ###########################################################################
    # Settings View
    def show_settings(self):
        DIE.UI.SetupView.Show(self.config_file_name)

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
    flags = idaapi.PLUGIN_UNL
    comment = "Dynamic IDA Enrichment plugin (aka. DIE)"
    help = "Help if a matter of trust."
    wanted_name = "DIE"
    wanted_hotkey = ""

    def init(self):
        global die_manager

        if not 'die_manager' in globals():

            die_manager = DieManager()
            if die_manager.add_menu_items():
                idaapi.msg("Failed to initialize DIE.\n")
                die_manager.del_menu_items()
                del die_manager
                return idaapi.PLUGIN_SKIP

            else:
                die_manager.show_logo()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        global die_manager

        if die_manager is not None:
            if not die_manager.die_db.is_saved:
                response = idc.AskYN(1, "One more thing before you go... DIE DB was not saved, Would you like to save it now?")
                if response == 1:
                    die_manager.save_db()


def PLUGIN_ENTRY():
    return die_plugin_t()






