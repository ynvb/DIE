__author__ = 'yanivb'

from PySide import QtGui, QtCore

import idaapi
import idautils
import idc
from idaapi import PluginForm

import DIE.Lib.DIEDb
import DIE.UI.FunctionViewEx


class ValueView(PluginForm):
    """
    DIE Value View
    """

    def __init__(self):

        super(ValueView, self).__init__()
        self.die_db = None
        self.function_view = None
        self.highligthed_items = []

    def Show(self):

        return PluginForm.Show(self,
                               "Value View",
                               options=PluginForm.FORM_PERSIST)

    def OnCreate(self, form):
        """
        Called when the view is created
        """
        self.die_db = DIE.Lib.DIEDb.get_db()
        self.function_view = DIE.UI.FunctionViewEx.get_view()

        # Get parent widget
        self.parent = self.FormToPySideWidget(form)

        self.valueModel = QtGui.QStandardItemModel()
        self.valueTreeView = QtGui.QTreeView()
        self.valueTreeView.setExpandsOnDoubleClick(False)

        self.valueTreeView.doubleClicked.connect(self.itemDoubleClickSlot)

        self._model_builder(self.valueModel)
        self.valueTreeView.setModel(self.valueModel)

        # Toolbar
        self.value_toolbar = QtGui.QToolBar()

        # Value type combobox
        type_list = []
        if self.die_db:
            type_list = self.die_db.get_all_value_types()
            type_list.insert(0, "All Values")

        self.value_type_combo = QtGui.QComboBox()
        self.value_type_combo.addItems(type_list)
        self.value_type_combo.activated[str].connect(self.on_value_type_combobox_change)

        self.value_type_label = QtGui.QLabel("Value Type:  ")
        self.value_toolbar.addWidget(self.value_type_label)
        self.value_toolbar.addWidget(self.value_type_combo)

        # Layout
        layout = QtGui.QGridLayout()
        layout.addWidget(self.value_toolbar)
        layout.addWidget(self.valueTreeView)

        self.parent.setLayout(layout)

    def isVisible(self):
        """
        Is valueview visible
        @return: True if visible, otherwise False
        """
        try:
            return self.valueTreeView.isVisible()
        except:
            return False

    def _model_builder(self, model):
        """
        Build the function model.
        @param model: QStandardItemModel object
        """

        model.clear()  # Clear the model
        root_node = model.invisibleRootItem()

        model.setHorizontalHeaderLabels(("Type", "Score", "Value", "Description", "Raw Value"))

        if self.die_db is None:
            return

        value_list = self.die_db.get_all_values()
        for value in value_list:
            value_data_item_list = self._make_value_item(value)
            root_node.appendRow(value_data_item_list)

    def _make_value_type_item(self, type):
        """
        Make a value item type
        @param type: item type
        """

        item_value_type = QtGui.QStandardItem(type)
        item_value_type.setEditable(False)

        return [item_value_type]

    def _make_value_item(self, value):
        """
        Make a value model item
        @param value: dbParsed_Value object
        @return: a list of items for this row.
        """
        null_item = QtGui.QStandardItem()
        null_item.setEditable(False)
        null_item.setData(value.type, role=DIE.UI.ValueType_Role)
        null_item.setData(value.__hash__(), role=DIE.UI.Value_Role)

        item_value_score = QtGui.QStandardItem(str(value.score))
        item_value_score.setEditable(False)

        item_value_data = QtGui.QStandardItem(value.data)
        ea_list = self.die_db.get_parsed_value_contexts(value)
        item_value_data.setData(ea_list, role=DIE.UI.ContextList_Role)
        item_value_data.setEditable(False)

        item_value_desc = QtGui.QStandardItem(value.description)
        item_value_desc.setEditable(False)

        item_value_raw = QtGui.QStandardItem(value.raw)
        item_value_raw.setEditable(False)

        return [null_item, item_value_score, item_value_data, item_value_desc, item_value_raw]


###############################################################################################
# Highlight Items
#
###############################################################################################


    def highlight_item(self, item):
        """
        Highlight a single item
        @param item: module item
        """
        try:
            item.setBackground(QtCore.Qt.GlobalColor.yellow)
            cur_font = item.font()
            cur_font.setBold(True)
            item.setFont(cur_font)

        except Exception as ex:
            idaapi.msg("Error while highlighting item: %s\n" % ex)

    def highlight_item_row(self, item):
        """
        highlight the entire row containing a table item
        @param item: table item
        """
        try:
            if not item.index().isValid():
                return

            parent = item.parent()
            if parent is None:
                parent = item

            if not parent.hasChildren():
                self.highlight_item(parent)
                return

            row = item.row()
            column_num = parent.columnCount()

            for column in xrange(0, column_num):
                if self.valueModel.hasIndex(row, column, parent.index()):
                    cur_index = self.valueModel.index(row, column, parent.index())

                    self.highlight_item(self.valueModel.itemFromIndex(cur_index))
                    persistent_index = QtCore.QPersistentModelIndex(cur_index)
                    self.highligthed_items.append(persistent_index)

        except Exception as ex:
            idaapi.msg("Error while highlighting item row: %s\n" % ex)


    def clear_highlights(self):
        """
        Clear all highlighted items
        @return:
        """
        try:
            self.valueTreeView.collapseAll()

            for persistent_index in self.highligthed_items:
                if persistent_index.isValid():
                    item = self.valueModel.itemFromIndex(persistent_index)
                    item.setBackground(QtCore.Qt.GlobalColor.white)
                    cur_font = item.font()
                    cur_font.setBold(False)
                    item.setFont(cur_font)

            self.highligthed_items = []

        except Exception as ex:
            idaapi.msg("Error while clearing highlights: %s\n" % ex)

###############################################################################################
#  Find Items
#
###############################################################################################
    def find_value(self, value):
        """
        Find and highlight a function in current module
        @param value object (of type dbParsed_Value)
        """
        try:
            root_index = self.valueModel.index(0, 0)
            if not root_index.isValid():
                return

            matched_items = self.valueModel.match(root_index, DIE.UI.Value_Role, value.__hash__(), -1,
                                                  QtCore.Qt.MatchFlag.MatchRecursive | QtCore.Qt.MatchFlag.MatchExactly)

            for index in matched_items:
                if not index.isValid():
                    continue

                item = self.valueModel.itemFromIndex(index)
                self.valueTreeView.expand(index)
                self.valueTreeView.scrollTo(index, QtGui.QAbstractItemView.ScrollHint.PositionAtTop)
                self.highlight_item_row(item)

        except Exception as ex:
            idaapi.msg("Error while finding value: %s\n" % ex)


###############################################################################################
#  Slots
#
###############################################################################################


    @QtCore.Slot(QtCore.QModelIndex)
    def itemDoubleClickSlot(self, index):
        """
        TreeView DoubleClicked Slot.
        @param index: QModelIndex object of the clicked tree index item.
        @return:
        """

        func_context_list = index.data(role=DIE.UI.ContextList_Role)
        try:
            if self.function_view is None:
                self.function_view = DIE.UI.FunctionViewEx.get_view()

            if func_context_list is not None and len(func_context_list) > 0:
                if not self.function_view.isVisible():
                    self.function_view.Show()

                self.function_view.find_context_list(func_context_list)

        except Exception as ex:
            idaapi.msg("Error while loading function view: %s\n" % ex)

    def on_value_type_combobox_change(self, value_type):
        """
        Value type Combobox item changed slot.
        """
        if value_type == "All Values":
            if not self.valueTreeView.model() is self.valueModel:
                self.valueTreeView.setModel(self.valueModel)
            return

        valuetypeProxyModel = QtGui.QSortFilterProxyModel()
        valuetypeProxyModel.setFilterRole(DIE.UI.ValueType_Role)
        valuetypeProxyModel.setFilterRegExp(value_type)

        valuetypeProxyModel.setSourceModel(self.valueModel)
        self.valueTreeView.setModel(valuetypeProxyModel)


# Singelton
_value_view = None
def initialize():
    global _value_view
    _value_view = ValueView()


def get_view():
    return _value_view