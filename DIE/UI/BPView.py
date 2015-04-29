from DIE.Lib import BpHandler

__author__ = 'yanivb'

from idaapi import PluginForm
from PySide import QtGui, QtCore
import DIE.UI.Die_Icons


class BreakpointView(PluginForm):
    """
    DIE Value View
    """
    def __init__(self):

        super(BreakpointView, self).__init__()
        self.bp_handler = None
        self.bp_tree_widget = None
        self.die_icons = None

    def Show(self):
        return PluginForm.Show(self,
                               "Breakpoint View",
                               options=PluginForm.FORM_PERSIST)
    def OnCreate(self, form):
        """
        Called when the view is created
        """
        self.bp_tree_widget = QtGui.QTreeWidget()
        self.bp_handler = BpHandler.get_bp_handler()
        self.die_icons = DIE.UI.Die_Icons.get_die_icons()

        # Get parent widget
        self.parent = self.FormToPySideWidget(form)

        self._add_parser_data()

        toolbar = QtGui.QToolBar()
        action_refresh = QtGui.QAction(self.die_icons.icon_refresh, "Refresh", toolbar)
        action_refresh.triggered.connect(self.refresh)
        toolbar.addAction(action_refresh)


        layout = QtGui.QGridLayout()
        layout.addWidget(toolbar)
        layout.addWidget(self.bp_tree_widget)

        self.parent.setLayout(layout)

    def refresh(self):
        """
        Reload the view with current values
        """
        self._add_parser_data()

    def _add_parser_data(self):
        """
        Add data to the breakpoint widget model
        """
        if self.bp_tree_widget is not None:
            self.bp_tree_widget.clear()
        else:
            self.bp_tree_widget = QtGui.QTreeWidget()

        root_item = self.bp_tree_widget.invisibleRootItem()

        self.bp_tree_widget.setHeaderLabel("Breakpoints")

        # Excluded Modules
        module_item = QtGui.QTreeWidgetItem()
        module_item.setText(0, "Excluded Modules")
        module_item.setFlags(QtCore.Qt.ItemIsEnabled)

        row = 0
        for module in self.bp_handler.excluded_modules:
            current_row_item = QtGui.QTreeWidgetItem()
            current_row_item.setFlags(QtCore.Qt.ItemIsEnabled)
            current_row_item.setText(0, module)
            module_item.insertChild(row, current_row_item)
            row += 1

        # Excluded Functions
        function_item = QtGui.QTreeWidgetItem()
        function_item.setText(0, "Excluded Functions")
        function_item.setFlags(QtCore.Qt.ItemIsEnabled)

        row = 0
        for function in self.bp_handler.excluded_funcNames:
            current_row_item = QtGui.QTreeWidgetItem()
            current_row_item.setFlags(QtCore.Qt.ItemIsEnabled)
            current_row_item.setText(0, function)
            function_item.insertChild(row, current_row_item)
            row += 1

        # Excluded Addresses
        ea_item = QtGui.QTreeWidgetItem()
        ea_item.setText(0, "Excluded Addresses")
        ea_item.setFlags(QtCore.Qt.ItemIsEnabled)

        row = 0
        for ea in self.bp_handler.excluded_bp_ea:
            current_row_item = QtGui.QTreeWidgetItem()
            current_row_item.setFlags(QtCore.Qt.ItemIsEnabled)
            current_row_item.setText(0, hex(ea))
            ea_item.insertChild(row, current_row_item)
            row += 1

        current_row = 0
        if module_item.childCount() > 0:
            root_item.insertChild(current_row, module_item)
            current_row += 1
        if function_item.childCount() > 0:
            root_item.insertChild(current_row, function_item)
            current_row += 1
        if ea_item.childCount() > 0:
            root_item.insertChild(current_row, ea_item)
            current_row += 1


_bp_view = None

def get_view():
    return _bp_view

def initialize():
    global _bp_view
    _bp_view = BreakpointView()