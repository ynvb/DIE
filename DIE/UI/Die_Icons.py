from DIE.Lib import DieConfig
import idaapi
import os
import DIE.Lib.DieConfig
from PySide import QtGui


class DieIcons():
    """
    DIE Icons
    """

    ##########################################################################
    # Icons Filenames

    __FUNC_ICON = "func.png"
    __V_ICON = "v.png"
    __X_ICON = "x.png"
    __QUESTION_ICON = "question_mark.png"
    __MORE_ICON = "more.png"
    __INFO_ICON = "info.png"
    __EXCLAMATION_ICON = "exclamation-mark.png"
    __DBG_ICON = "dbg.png"
    __STOP_ICON = "stop.png"
    __PLUGINS_ICON = "plugins.png"
    __SAVE_ICON = "save.png"
    __DIE_ICON = "die.png"
    __FUNCVIEW_ICON = "funcview.png"
    __LOAD_ICON = "load.png"
    __PLAY_ICON = "play.png"
    __SETTINGS_ICON = "settings.png"
    __REFRESH_ICON = "refresh.png"
    __VALUVIEW_ICON = "valueview.png"
    __DBGALL_ICON = "dbg_all.png"

    def __init__(self, icons_path="icons"):

        self.die_config = DieConfig.get_config()

        self.icons_path = self.die_config.icons_path

        if not os.path.exists(self.icons_path):
            idaapi.msg("Error: could not locate DIE icons directory.\n")
            return

        self._load_icons()

    def _load_icons(self):
        """
        Load Icons
        @return: True if icons loaded successfully, otherwise False.
        """
        ### Function Icon
        icon_path = os.path.join(self.icons_path, self.__FUNC_ICON)
        self.icon_function = self.load_icon(icon_path)

        ### V Icon
        icon_path = os.path.join(self.icons_path, self.__V_ICON)
        self.icon_v = self.load_icon(icon_path)

        ### X Icon
        icon_path = os.path.join(self.icons_path, self.__X_ICON)
        self.icon_x = self.load_icon(icon_path)

        ### Question Icon
        icon_path = os.path.join(self.icons_path, self.__QUESTION_ICON)
        self.icon_question = self.load_icon(icon_path)

        ### More Icon
        icon_path = os.path.join(self.icons_path, self.__MORE_ICON)
        self.icon_more = self.load_icon(icon_path)

        ### Info Icon
        icon_path = os.path.join(self.icons_path, self.__INFO_ICON)
        self.icon_info = self.load_icon(icon_path)

        ### Exclamation Icon

        icon_path = os.path.join(self.icons_path, self.__EXCLAMATION_ICON)
        self.icon_exclama = self.load_icon(icon_path)

        # Debug Icon

        icon_path = os.path.join(self.icons_path, self.__DBG_ICON)
        self.icon_dbg = self.load_icon(icon_path)

        # Plugins Icon

        icon_path = os.path.join(self.icons_path, self.__PLUGINS_ICON)
        self.icon_plugins = self.load_icon(icon_path)

        # Stop Icon

        icon_path = os.path.join(self.icons_path, self.__STOP_ICON)
        self.icon_stop = self.load_icon(icon_path)

        # Save Icon

        icon_path = os.path.join(self.icons_path, self.__SAVE_ICON)
        self.icon_save = self.load_icon(icon_path)

        # DIE Icon

        icon_path = os.path.join(self.icons_path, self.__DIE_ICON)
        self.icon_die = self.load_icon(icon_path)

        # Function View Icon

        icon_path = os.path.join(self.icons_path, self.__FUNCVIEW_ICON)
        self.icon_funcview = self.load_icon(icon_path)

        # Value View Icon

        icon_path = os.path.join(self.icons_path, self.__VALUVIEW_ICON)
        self.icon_valueview = self.load_icon(icon_path)

        # Load Icon

        icon_path = os.path.join(self.icons_path, self.__LOAD_ICON)
        self.icon_load = self.load_icon(icon_path)

        # Play Icon

        icon_path = os.path.join(self.icons_path, self.__PLAY_ICON)
        self.icon_play = self.load_icon(icon_path)

        # Settings Icon

        icon_path = os.path.join(self.icons_path, self.__SETTINGS_ICON)
        self.icon_settings = self.load_icon(icon_path)

        # Refresh Icons

        icon_path = os.path.join(self.icons_path, self.__REFRESH_ICON)
        self.icon_refresh = self.load_icon(icon_path)

        # Debug All Icon

        icon_path = os.path.join(self.icons_path, self.__DBGALL_ICON)
        self.icon_dbg_all = self.load_icon(icon_path)


    def load_icon(self, icon_path):
        """
        Load a single icon
        @param icon_path: full path to the icon file
        @return: the loaded icon object or None
        """
        icon_path = os.path.join(os.path.dirname(__file__), "..", "icons", icon_path)
        try:
            if os.path.exists(icon_path):
                return QtGui.QIcon(icon_path)
            else:
                return None
        except:
            return None



_die_icons = None
def initlialize():
    global _die_icons
    _die_icons = DieIcons()


def get_die_icons():
    return _die_icons















