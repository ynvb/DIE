from DIE.Lib import DieConfig

__author__ = 'yanivb'

import idaapi
import os
import DIE.Lib.DieConfig
from PySide import QtGui


class DieIcons():
    """
    DIE Icons
    """

    def __init__(self, icons_path="icons"):

        self.die_config = DieConfig.get_config()

        #install_path = idaapi.idadir("Plugins\DIE")
        self.icons_path = self.die_config.icons_path

        #if install_path is None or not os.path.exists(install_path):
        #    print "Error: could not locate DIE plugin directory"
        #    return

        #self.icons_path = (install_path + '\\' + icons_path)

        if not os.path.exists(self.icons_path):
            print "Error: could not locate DIE icons directory."
            return

        ##########################################################################
        # Icons Filenames

        self.__func_icon = "func.png"
        self.__v_icon = "v.png"
        self.__x_icon = "x.png"
        self.__question_icon = "question_mark.png"
        self.__more_icon = "more.png"
        self.__info_icon = "info.png"
        self.__exclamation_icon = "exclamation-mark.png"
        self.__dbg_icon = "dbg.png"
        self.__stop_icon = "stop.png"
        self.__plugins_icon = "plugins.png"
        self.__save_icon = "save.png"
        self.__DIE_icon = "die.png"
        self.__funcview_icon = "funcview.png"
        self.__load_icon = "load.png"
        self.__play_icon = "play.png"
        self.__settings_icon = "settings.png"
        self.__refresh_icon = "refresh.png"
        self.__valuview_icon = "valueview.png"
        self.__dbgall_icon = "dbg_all.png"

        self._load_icons()

    def _load_icons(self):
        """
        Load Icons
        @return: True if icons loaded successfully, otherwise False.
        """
        ### Function Icon
        icon_path = self.icons_path + "\\" + self.__func_icon
        self.icon_function = self.load_icon(icon_path)

        ### V Icon
        icon_path = self.icons_path + "\\" + self.__v_icon
        self.icon_v = self.load_icon(icon_path)

        ### X Icon
        icon_path = self.icons_path + "\\" + self.__x_icon
        self.icon_x = self.load_icon(icon_path)

        ### Question Icon
        icon_path = self.icons_path + "\\" + self.__question_icon
        self.icon_question = self.load_icon(icon_path)

        ### More Icon
        icon_path = self.icons_path + "\\" + self.__more_icon
        self.icon_more = self.load_icon(icon_path)

        ### Info Icon
        icon_path = self.icons_path + "\\" + self.__info_icon
        self.icon_info = self.load_icon(icon_path)

        ### Exclamation Icon

        icon_path = self.icons_path + "\\" + self.__exclamation_icon
        self.icon_exclama = self.load_icon(icon_path)

        # Debug Icon

        icon_path = self.icons_path + "\\" + self.__dbg_icon
        self.icon_dbg = self.load_icon(icon_path)

        # Plugins Icon

        icon_path = self.icons_path + "\\" + self.__plugins_icon
        self.icon_plugins = self.load_icon(icon_path)

        # Stop Icon

        icon_path = self.icons_path + "\\" + self.__stop_icon
        self.icon_stop = self.load_icon(icon_path)

        # Save Icon

        icon_path = self.icons_path + "\\" + self.__save_icon
        self.icon_save = self.load_icon(icon_path)

        # DIE Icon

        icon_path = self.icons_path + "\\" + self.__DIE_icon
        self.icon_die = self.load_icon(icon_path)

        # Function View Icon

        icon_path = self.icons_path + "\\" + self.__funcview_icon
        self.icon_funcview = self.load_icon(icon_path)

        # Value View Icon

        icon_path = self.icons_path + "\\" + self.__valuview_icon
        self.icon_valueview = self.load_icon(icon_path)

        # Load Icon

        icon_path = self.icons_path + "\\" + self.__load_icon
        self.icon_load = self.load_icon(icon_path)

        # Play Icon

        icon_path = self.icons_path + "\\" + self.__play_icon
        self.icon_play = self.load_icon(icon_path)

        # Settings Icon

        icon_path = self.icons_path + "\\" + self.__settings_icon
        self.icon_settings = self.load_icon(icon_path)

        # Refresh Icons

        icon_path = self.icons_path + "\\" + self.__refresh_icon
        self.icon_refresh = self.load_icon(icon_path)

        # Debug All Icon

        icon_path = self.icons_path + "\\" + self.__dbgall_icon
        self.icon_dbg_all = self.load_icon(icon_path)


    def load_icon(self, icon_path):
        """
        Load a single icon
        @param icon_path: full path to the icon file
        @return: the loaded icon object or None
        """

        try:
            if os.path.exists(icon_path):
                return QtGui.QIcon(icon_path)
            else:
                return None
        except:
            return None

_die_icons = DieIcons()

def get_die_icons():
    return _die_icons















