from awesome.context import ignored
import sark

__author__ = 'yanivb'

import idaapi
import idautils
import idc
from idaapi import PluginForm
from PySide import QtGui, QtCore

import DIE.UI.Die_Icons
import DIE.UI.ValueViewEx
import DIE.UI.ParserView
import DIE.UI.BPView

import DIE.Lib.IDAConnector
import DIE.Lib.DIEDb
import DIE.Lib.BpHandler

class FunctionView(PluginForm):
    """
    DIE Function View
    """

    def __init__(self):

        super(FunctionView, self).__init__()
        self.value_view = None
        self.bp_handler = None
        self.die_icons = None
        self.die_db = None
        self.highligthed_items = []

    def Show(self):
        # Reset highlighted items
        self.highligthed_items = []

        return PluginForm.Show(self,
                               "Function View",
                               options=PluginForm.FORM_PERSIST)
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """
        self.value_view = DIE.UI.ValueViewEx.get_view()
        self.bp_handler = DIE.Lib.BpHandler.get_bp_handler()
        self.die_icons = DIE.UI.Die_Icons.get_die_icons()
        self.die_db = DIE.Lib.DIEDb.get_db()

        # Get parent widget
        self.parent = self.FormToPySideWidget(form)

        self.functionModel = QtGui.QStandardItemModel()
        self.functionTreeView = QtGui.QTreeView()
        self.functionTreeView.setExpandsOnDoubleClick(False)
        #self.functionTreeView.setSortingEnabled(True)

        delegate = TreeViewDelegate(self.functionTreeView)
        self.functionTreeView.setItemDelegate(delegate)

        self.functionTreeView.doubleClicked.connect(self.itemDoubleClickSlot)

        self._model_builder(self.functionModel)
        self.functionTreeView.setModel(self.functionModel)

        self.functionTreeView.setColumnWidth(0, 200)
        self.functionTreeView.setColumnWidth(1, 20)
        self.functionTreeView.setColumnWidth(2, 20)
        self.functionTreeView.setColumnWidth(3, 20)
        self.functionTreeView.setColumnWidth(4, 250)
        self.functionTreeView.setColumnWidth(5, 100)
        self.functionTreeView.setColumnWidth(6, 20)
        self.functionTreeView.setColumnWidth(7, 450)
        self.functionTreeView.setColumnWidth(8, 20)
        self.functionTreeView.setColumnWidth(9, 450)

        # Context menus
        self.functionTreeView.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.functionTreeView.customContextMenuRequested.connect(self.onCustomContextMenu)

        # Actions
        self.context_menu_param = None  # Parameter to be passed to context menu slots

        action_exclude_func = QtGui.QAction("Exclude Function", self.functionTreeView, triggered=lambda: self.on_exclude_func(self.context_menu_param))
        action_exclude_func_adrs = QtGui.QAction("Exclude All Function Calls", self.functionTreeView, triggered=lambda: self.on_exclude_func_adrs(self.context_menu_param))
        action_exclude_ea = QtGui.QAction("Exclude Address", self.functionTreeView, triggered=lambda: self.on_exclude_ea(self.context_menu_param))
        action_exclude_library = QtGui.QAction("Exclude Library", self.functionTreeView, triggered=lambda: self.on_exclude_library(self.context_menu_param))
        action_value_detail = QtGui.QAction("Inspect Value Details", self.functionTreeView, triggered=lambda: self.on_value_detail(self.context_menu_param))

        # Function ContextMenu
        self.function_context_menu = QtGui.QMenu(self.functionTreeView)
        self.function_context_menu.addAction(action_exclude_func)
        self.function_context_menu.addAction(action_exclude_library)
        self.function_context_menu.addAction(action_exclude_func_adrs)

        # Function ea ContextMenu
        self.ea_context_menu = QtGui.QMenu(self.functionTreeView)
        self.ea_context_menu.addAction(action_exclude_ea)

        # Argument value ContextMenu
        self.value_context_menu = QtGui.QMenu(self.functionTreeView)
        self.value_context_menu.addAction(action_value_detail)

        # Therad ComboBox
        threads = []
        if self.die_db is not None:
            threads = self.die_db.get_thread_list()

        thread_id_list = []
        thread_id_list.append("All Threads")
        for thread in threads:
            thread_id_list.append(str(thread.thread_num))

        self.thread_id_combo = QtGui.QComboBox()
        self.thread_id_combo.addItems(thread_id_list)
        self.thread_id_combo.activated[str].connect(self.on_thread_combobox_change)

        self.thread_id_label = QtGui.QLabel("Thread:  ")

        # Toolbar
        self.function_toolbar = QtGui.QToolBar()
        self.function_toolbar.addWidget(self.thread_id_label)
        self.function_toolbar.addWidget(self.thread_id_combo)

        # Grid
        layout = QtGui.QGridLayout()
        layout.addWidget(self.function_toolbar)
        layout.addWidget(self.functionTreeView)

        self.parent.setLayout(layout)

    def OnClose(self, form):
        idaapi.msg("Closed\n")

    def isVisible(self):
        """
        Is functionview visible
        @return: True if visible, otherwise False
        """
        try:
            return self.functionTreeView.isVisible()
        except:
            return False

    def _model_builder(self, model):
        """
        Build the function model.
        @param model: QStandardItemModel object
        """
        model.clear()  # Clear the model
        root_node = model.invisibleRootItem()

        self._make_model_headers(model)

        if self.die_db is None:
            return

        # Add db functions to the model
        for function in self.die_db.get_functions():
            item_list_func = self._make_function_item(function)

            if function.is_lib_func:  # Color library function
                for tmp_item in item_list_func:
                    tmp_item.setBackground(QtGui.QColor(184, 223, 220))

            item_function = item_list_func[0]
            root_node.appendRow(item_list_func)

            # Add function contexts ea\occurrences for the current function
            func_context_dict = self.die_db.get_function_context_dict(function)

            for function_context_ea in func_context_dict:
                function_context_list = func_context_dict[function_context_ea]
                if not len(function_context_list) > 0:
                    continue

                item_func_context_list = self._make_function_ea_item(function_context_list[0])
                item_func_context_ea = item_func_context_list[0]
                item_function.appendRow(item_func_context_list)

                occurrence_num = 0
                for function_context in function_context_list:
                    item_func_context_list = self._make_func_occur_item(function_context, occurrence_num)
                    item_func_context = item_func_context_list[0]
                    item_func_context_ea.appendRow(item_func_context_list)

                    self._insert_thread_data(item_function, function_context.thread_id)
                    self._insert_thread_data(item_func_context_ea, function_context.thread_id)

                    # Add function arguments to each context
                    current_call_values = self.die_db.get_call_values(function_context)
                    current_ret_values = self.die_db.get_return_values(function_context)
                    curret_ret_arg_value = self.die_db.get_return_arg_value(function_context)

                    for arg_index in xrange(0, function.arg_num):
                        try:
                            current_arg = self.die_db.get_function_arg(function, arg_index)
                            self._add_model_arg_value(item_func_context,
                                                       current_call_values[arg_index],
                                                       current_ret_values[arg_index],
                                                       current_arg.name,
                                                       current_arg.type)
                        except IndexError:
                            break

                    ret_arg = self.die_db.get_function_arg(function, -1)
                    if ret_arg is None:
                        ret_arg_type = "VOID"
                    else:
                        ret_arg_type = ret_arg.type

                    # Add return argument
                    self._add_model_arg_value(item_func_context,
                                               None,
                                               curret_ret_arg_value,
                                               "ret_arg",
                                               ret_arg_type)

                    # Increment occurrence counter
                    occurrence_num += 1

        # Add non-executed function to the model
        # for func_ea in idautils.Functions():
        #     func_name = DIE.Lib.IDAConnector.get_function_name(func_ea)
        #
        #     if self.die_db.get_function_by_name(func_name) is None:
        #         item_list_func = self._make_nonexec_function_time(func_name)
        #
        #         if function.is_lib_func:  # Color library function
        #             for tmp_item in item_list_func:
        #                 tmp_item.setBackground(QtGui.QColor(255, 0, 0, 127))
        #
        #         root_node.appendRow(item_list_func)


    def _make_model_headers(self, model):
        """
        Set the model horizontal header data
        @param model: the QStandardItemModel which headers should be set
        """
        ### Function Header
        item_header = QtGui.QStandardItem("Function")
        item_header.setToolTip("Function Name")
        model.setHorizontalHeaderItem(0, item_header)

        ### Call number header
        item_header = QtGui.QStandardItem("#")
        item_header.setToolTip("Number of calls preformed to this function")
        model.setHorizontalHeaderItem(1, item_header)

        ### Indirect Header
        item_header = QtGui.QStandardItem("I")
        item_header.setToolTip("Indirect Call")
        model.setHorizontalHeaderItem(2, item_header)

        ### Indirect Header
        item_header = QtGui.QStandardItem("N")
        item_header.setToolTip("New Function")
        model.setHorizontalHeaderItem(3, item_header)

        ### Indirect Header
        item_header = QtGui.QStandardItem("Type")
        item_header.setToolTip("Argument Type")
        model.setHorizontalHeaderItem(4, item_header)

        ### New Function Header
        item_header = QtGui.QStandardItem("Name")
        item_header.setToolTip("Argument Name")
        model.setHorizontalHeaderItem(5, item_header)

        ### Call Value Icon Header
        item_header = QtGui.QStandardItem("")
        model.setHorizontalHeaderItem(6, item_header)

        ### Call Value Header
        item_header = QtGui.QStandardItem("Call Value")
        item_header.setToolTip("Argument`s value on function call")
        model.setHorizontalHeaderItem(7, item_header)

        ### Return Value Icon Header
        item_header = QtGui.QStandardItem("")
        model.setHorizontalHeaderItem(8, item_header)

        ### Return Value Header
        item_header = QtGui.QStandardItem("Return Value")
        item_header.setToolTip("Argument`s value on function return")
        model.setHorizontalHeaderItem(9, item_header)

    def _make_thread_id_data(self, thread_id):
        """
        Delimit thread_id data in order to support filtering\sorting on multi-thread data items
        @param thread_id: thread id to normalize
        @return: a normalized string of the thread_id to be used sa data for ThreadId_Role
        """
        return "t%st" % str(thread_id)

    def _insert_thread_data(self, item, thread_id):
        """
        Insert thread_id data into a model item.
        The value found in thread_id argument will be delimited by the _make_thread_id_data function
        (e.g: thread_id 123 will become 't123t')
        the delimited value will then be appended to a string of concatenated (unique) child-item thread-ids
        (for example a item data value can be "a123aa5672aa11112a") for threads 123, 5672 and 111112
        @param item: the model item to add the data to
        @param thread_id: thread_id number
        @return: True if thread data was successfully added to item, otherwise False
        """
        try:
            current_thread_id = self._make_thread_id_data(thread_id)
            thread_data = item.data(role=DIE.UI.ThreadId_Role)


            if thread_data is None:
                item.setData(current_thread_id, role=DIE.UI.ThreadId_Role)

            elif not current_thread_id in thread_data:
                item.setData(thread_data + current_thread_id, role=DIE.UI.ThreadId_Role)

            return True

        except Exception as ex:
            idaapi.msg("Error while inserting thread data: %s\n" %ex)
            return False

    def _make_function_item(self, function):
        """
        Build a tree item for a function name (level-0)
        @param function: dbFunction object
        @return: QStandradItemModel item for the function
        """
        function_txt = "%s" % function.function_name

        item_function = QtGui.QStandardItem(self.die_icons.icon_function, function_txt)
        item_function.setData(function, role=DIE.UI.Function_Role)

        function_count = self.die_db.count_function_occurs(function)
        item_function_count = QtGui.QStandardItem(str(function_count))

        item_function_count.setEditable(False)
        item_function.setEditable(False)

        item_list = [item_function,
                     item_function_count,
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem()]

        return item_list

    def _make_nonexec_function_time(self, function_name):
        """
        Build a tree item for a function name (for a non-executed function)
        @type: String
        @param function_name: Function name
        @return:
        """

        item_function = QtGui.QStandardItem(self.die_icons.icon_function, function_name)
        item_function_count = QtGui.QStandardItem("0")

        item_function_count.setEditable(False)
        item_function.setEditable(False)

        item_list = [item_function, item_function_count]

        return item_list

    def _make_function_ea_item(self, function_context):
        """
        Build a tree item for a function_ea node (level-1)
        @param function_context: a dbFunction_Context object
        @return: QStandradItemModel item for the function context
        """
        calling_function_start = None
        with ignored(sark.exceptions.SarkNoFunction):
            calling_function_start = sark.Function(function_context.calling_ea).startEA

        if calling_function_start is not None:
            call_offset = function_context.calling_ea - calling_function_start
            func_ea_txt = "%s+%s" % (function_context.calling_func_name, hex(call_offset))
        else:
            func_ea_txt = "[%s]:%s" % (function_context.calling_func_name, hex(function_context.calling_ea))

        item_func_context_ea = QtGui.QStandardItem(func_ea_txt)
        item_func_context_ea.setEditable(False)
        item_func_context_ea.setData(hex(function_context.calling_ea), role=QtCore.Qt.ToolTipRole)
        item_func_context_ea.setData(function_context, role=DIE.UI.FunctionContext_Role)
        item_func_context_ea.setData(id(function_context), role=DIE.UI.ContextId_Role)  # Used for module look-ups

        item_func_is_indirect = QtGui.QStandardItem()
        item_func_is_indirect.setEditable(False)
        if function_context.is_indirect:
            item_func_is_indirect.setIcon(self.die_icons.icon_v)

        item_func_is_new = QtGui.QStandardItem()
        item_func_is_new.setEditable(False)
        if function_context.is_new_func:
            item_func_is_new.setIcon(self.die_icons.icon_v)

        item_list = [item_func_context_ea,
                     QtGui.QStandardItem(),
                     item_func_is_indirect,
                     item_func_is_new,
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem()]

        return item_list

    def _make_func_occur_item(self, function_context, occur_num):
        """
        Build a tree item for function occurrence (level-2)
        @param function_context: a dbFunction_Context object
        @param occur_num: occurrence number
        @return: QStandradItemModel item for the function occurrence
        """
        func_occur_txt = "Occur %s" % str(occur_num)
        item_func_context = QtGui.QStandardItem(func_occur_txt)
        item_func_context.setColumnCount(5)
        item_func_context.setEditable(False)
        item_func_context.setData(function_context, role=DIE.UI.FunctionContext_Role)
        item_func_context.setData(id(function_context), role=DIE.UI.ContextId_Role)  # Used for module look-ups
        item_func_context.setData(self._make_thread_id_data(function_context.thread_id), role=DIE.UI.ThreadId_Role)

        item_list = [item_func_context,
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem(),
                     QtGui.QStandardItem()]

        return item_list

    def _add_model_arg_value(self, parent, call_value, ret_value, arg_name, arg_type, nest_depth=0):
        """
        Add a debug value
        @param parent:
        @param call_value:
        @param ret_value:
        @param arg_name:
        @param arg_type:
        @return:
        """
        arg_count = parent.rowCount()
        this_row_item = QtGui.QStandardItem("")
        this_row_item.setData(parent.data(role=DIE.UI.ThreadId_Role), role=DIE.UI.ThreadId_Role)  # Inherit thread data from parent

        # Set indentation for argument types (for nested values)
        arg_ident = "  " * nest_depth
        arg_ident_type = arg_ident + arg_type

        item_parsed_val_flag_call = QtGui.QStandardItem()
        item_parsed_val_call = QtGui.QStandardItem()
        item_parsed_val_flag_ret = QtGui.QStandardItem()
        item_parsed_val_ret = QtGui.QStandardItem()

        # Get Call Value
        if call_value is not None:
            parsed_vals = self.die_db.get_parsed_values(call_value)
            this_row_item.setData(parsed_vals, role=DIE.UI.CallValue_Role)

            if parsed_vals is not None and len(parsed_vals) > 0:
                is_guessed, best_val = self.die_db.get_best_parsed_val(parsed_vals)
                item_parsed_val_call = QtGui.QStandardItem(best_val.data)
                if is_guessed:
                    item_parsed_val_flag_call.setIcon(self.die_icons.icon_question)

                if len(parsed_vals) > 1:  # If more the 1 item, show a combo-box
                    item_parsed_val_call.setData(parsed_vals, role=DIE.UI.ParsedValuesRole)
                    item_parsed_val_flag_call.setIcon(self.die_icons.icon_more)
                else:
                    item_parsed_val_call.setData(parsed_vals[0], role=DIE.UI.ParsedValueRole)

            else:
                parsed_val_data = "NULL"

                if call_value.derref_depth == 0:
                    parsed_val_data = "!MAX_DEREF!"

                if call_value.raw_value is not None:
                    parsed_val_data = hex(call_value.raw_value)

                if len(call_value.nested_values) > 0 or call_value.reference_flink is not None:
                    parsed_val_data = ""

                item_parsed_val_call = QtGui.QStandardItem(parsed_val_data)

        # Get return value
        if ret_value is not None:
            parsed_vals = self.die_db.get_parsed_values(ret_value)
            this_row_item.setData(parsed_vals, role=DIE.UI.RetValue_Role)

            # If len(parsed_vals)>1 create a combobox delegate.
            if parsed_vals:
                is_guessed, best_val = self.die_db.get_best_parsed_val(parsed_vals)
                item_parsed_val_ret = QtGui.QStandardItem(best_val.data)
                if is_guessed:
                    item_parsed_val_flag_ret.setIcon(self.die_icons.icon_question)

                if len(parsed_vals) > 1:  # If more the 1 item, show a combo-box
                    item_parsed_val_ret.setData(parsed_vals, role=DIE.UI.ParsedValuesRole)
                    item_parsed_val_flag_ret.setIcon(self.die_icons.icon_more)
                else:
                    item_parsed_val_ret.setData(parsed_vals[0], role=DIE.UI.ParsedValueRole)
            else:
                parsed_val_data = "NULL"

                if ret_value.derref_depth == 0:
                    parsed_val_data = "!MAX_DEREF!"

                if ret_value.raw_value is not None:
                    parsed_val_data = hex(ret_value.raw_value)

                if ret_value.nested_values or ret_value.reference_flink is not None:
                    parsed_val_data = ""

                item_parsed_val_ret = QtGui.QStandardItem(parsed_val_data)

            parent.setChild(arg_count, 0, this_row_item)
            parent.setChild(arg_count, 1, QtGui.QStandardItem())
            parent.setChild(arg_count, 2, QtGui.QStandardItem())
            parent.setChild(arg_count, 3, QtGui.QStandardItem())
            parent.setChild(arg_count, 4, QtGui.QStandardItem(arg_ident_type))
            parent.setChild(arg_count, 5, QtGui.QStandardItem(arg_name))

            parent.setChild(arg_count, 6, item_parsed_val_flag_call)
            parent.setChild(arg_count, 7, item_parsed_val_call)
            parent.setChild(arg_count, 8, item_parsed_val_flag_ret)
            parent.setChild(arg_count, 9, item_parsed_val_ret)

        # If current object contains reference values, add them to the module
        self._add_model_arg_ref(this_row_item, call_value, ret_value, nest_depth)

        # If current object is a container object, Add its members to the module
        self._add_model_container_members(this_row_item, call_value, ret_value, nest_depth)

    def _add_model_arg_ref(self, parent, call_value, ret_value, nest_depth=0):
        """
        Add a reference value to module
        @param parent:
        @param call_value:
        @param ret_value:
        @param nest_depth:
        @return:
        """
        # If call debug value is a reference
        if call_value is not None:
            if call_value.reference_flink is not None and not call_value.is_definitely_parsed:
                ref_val_call = self.die_db.get_dbg_value(call_value.reference_flink)
                ref_val_ret = None

                # Try to get the same reference from the return debug value.
                if ret_value is not None and ret_value.type == call_value.type:
                    if ret_value.reference_flink is not None and not ret_value.is_definitely_parsed:
                        ref_val_ret = self.die_db.get_dbg_value(ret_value.reference_flink)

                self._add_model_arg_value(parent, ref_val_call, ref_val_ret, ref_val_call.name, ref_val_call.type, nest_depth+1)

        # If return debug value is a reference (and call value is not)
        elif ret_value is not None:
            if ret_value.reference_flink is not None and not ret_value.is_definitely_parsed:
                ref_val = self.die_db.get_dbg_value(ret_value.reference_flink)
                self._add_model_arg_value(parent, None, ref_val, ref_val.name, ref_val.type, nest_depth+1)

    def _add_model_container_members(self, parent, call_value, ret_value, nest_depth=0):
        """
        Add container members to module
        @param parent:
        @param call_value:
        @param ret_value:
        @param nest_depth:
        @return:
        """
        # If call value is a container type (struct\union\etc)
        if call_value is not None and call_value.nested_values is not None:
            if call_value.nested_values:
                for index in xrange(0, len(call_value.nested_values)):
                    nested_val_call = self.die_db.get_dbg_value(call_value.nested_values[index])
                    nested_val_ret = None

                     # Try to get the same member from the return debug value.
                    if ret_value is not None and ret_value.type == call_value.type:
                        if ret_value.nested_values is not None:
                            if ret_value.nested_values:
                                nested_val_ret = self.die_db.get_dbg_value(ret_value.nested_values[index])

                    self._add_model_arg_value(parent, nested_val_call, nested_val_ret, nested_val_call.name, nested_val_call.type, nest_depth+1)

        # If return value is a container type (and call value is not)
        elif ret_value is not None:
            if ret_value.nested_values is not None:
                if ret_value.nested_values:
                    for nested_value in ret_value.nested_values:
                        nested_val_ret = self.die_db.get_dbg_value(nested_value)

                        self._add_model_arg_value(parent,
                                                  None,
                                                  nested_val_ret,
                                                  nested_val_ret.name,
                                                  nested_val_ret.type,
                                                  nest_depth+1)

    def reset_function_count(self, thread_id=None):
        """
        Reset the function count and set the count according to currently selected thread_id
        @param thread_id: currently selected thread_id
        """
        root_item = self.functionModel.item(0, 0)
        rows = root_item.rowCount()

        thread_id = self.thread_id_combo.currentText()

        for row in xrange(0, rows):
            cur_item = root_item.child(row, 0)
            function = cur_item.data(role=DIE.UI.Function_Role)

            if function is not None:
                count = 0
                if thread_id is None:
                     count = self.die_db.count_function_occurs(function)
                else:
                    count = self.die_db.count_function_occurs(function, int(thread_id))

                func_count_item = root_item.child(row, 1)
                func_count_item.setText(str(count))






###############################################################################################
#  Highlight Items.

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
            idaapi.msg("Error while highlighting item: %s\n" %ex)


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
                if self.functionModel.hasIndex(row, column, parent.index()):
                    cur_index = self.functionModel.index(row, column, parent.index())

                    self.highlight_item(self.functionModel.itemFromIndex(cur_index))
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
            self.functionTreeView.collapseAll()

            for persistent_index in self.highligthed_items:
                if persistent_index.isValid():
                    item = self.functionModel.itemFromIndex(persistent_index)
                    item.setBackground(QtCore.Qt.GlobalColor.white)
                    cur_font = item.font()
                    cur_font.setBold(False)
                    item.setFont(cur_font)

            self.highligthed_items = []

        except Exception as ex:
            idaapi.msg("Error while clearing highlights: %s\n" % ex)


###############################################################################################
#  Find Items.

    def find_function(self, function_name):
        """
        Find and highlight a function in current module
        @param function_name: Function name
        """
        self.clear_highlights()

        matched_items = self.functionModel.findItems(function_name)

        for item in matched_items:
            self.functionTreeView.expand(item.index())
            self.functionTreeView.scrollTo(item.index(), QtGui.QAbstractItemView.ScrollHint.PositionAtTop)
            self.highlight_item_row(item)

    def find_context_list(self, context_list):
        """
        Find and highlight a list of function contexts
        @param context_list: list of function contexts (of type dbFunction_Context)
        """
        try:
            self.clear_highlights()
            root_index = self.functionModel.index(0, 0)
            if not root_index.isValid():
                return

            for func_context in context_list:
                context_id = id(func_context)
                matched_items = self.functionModel.match(root_index, DIE.UI.ContextId_Role, context_id, -1, QtCore.Qt.MatchFlag.MatchRecursive|QtCore.Qt.MatchFlag.MatchExactly)

                for index in matched_items:
                    if not index.isValid():
                        continue
                    # Do not highlight "ea root" items, only occurrences of it.
                    if not index.data().startswith("Occur"):
                        continue

                    item = self.functionModel.itemFromIndex(index)
                    self.functionTreeView.expand(index)
                    self.functionTreeView.scrollTo(index, QtGui.QAbstractItemView.ScrollHint.PositionAtTop)
                    self.highlight_item_row(item)

            return True

        except Exception as ex:
            idaapi.msg("Error while looking up function context in FunctionView: %s\n" % ex)
            return False

###############################################################################################
#  Slots.

    @QtCore.Slot(QtCore.QModelIndex)
    def itemDoubleClickSlot(self, index):
        """
        TreeView DoubleClicked Slot.
        @param index: QModelIndex object of the clicked tree index item.
        @return:
        """
        function = index.data(role=DIE.UI.Function_Role)
        if function is not None:

            ea = function.function_start
            if function.is_lib_func:
                ea = function.proto_ea

            if ea is not None and ea is not idc.BADADDR:
                idc.Jump(ea)
                return True

        func_context = index.data(role=DIE.UI.FunctionContext_Role)
        if func_context is not None:
            ea = func_context.calling_ea
            if ea is not None and ea is not idc.BADADDR:
                idc.Jump(ea)
                return True

    @QtCore.Slot(QtCore.QPoint)
    def onCustomContextMenu(self, point):
        index = self.functionTreeView.indexAt(point)
        is_function_item = index.data(role=DIE.UI.Function_Role)
        is_func_context_item = index.data(role=DIE.UI.FunctionContext_Role)
        is_value_item = index.data(role=DIE.UI.ParsedValueRole)

        if is_function_item is not None:
            self.context_menu_param = is_function_item
            self.function_context_menu.exec_(self.functionTreeView.mapToGlobal(point))

        if is_func_context_item is not None:
            self.context_menu_param = is_func_context_item
            self.ea_context_menu.exec_(self.functionTreeView.mapToGlobal(point))

        if is_value_item is not None:
            self.context_menu_param = is_value_item
            self.value_context_menu.exec_(self.functionTreeView.mapToGlobal(point))

    @QtCore.Slot(str)
    def on_exclude_func(self, function):

        if not isinstance(function, DIE.Lib.DIEDb.dbFunction):
            if function is not None:
                raise ValueError("Wrong value sent to 'on_exclude_func_adrs': %s. excpected dbFunction_Context" % function.__class__)
            else:
                raise ValueError("Wrong value sent to 'on_exclude_func_adrs'")

        self.bp_handler.add_bp_funcname_exception(function.function_name)
        return

    @QtCore.Slot(str)
    def on_exclude_func_adrs(self, function):

        if not isinstance(function, DIE.Lib.DIEDb.dbFunction):
            if function is not None:
                raise ValueError("Wrong value sent to 'on_exclude_func_adrs': %s. excpected dbFunction_Context" % function.__class__)
            else:
                raise ValueError("Wrong value sent to 'on_exclude_func_adrs'")

        func_context_list = self.die_db.get_function_context_list(function)
        for func_context in func_context_list:
            self.bp_handler.add_bp_ea_exception(func_context.calling_ea)

        return

    @QtCore.Slot(str)
    def on_exclude_ea(self, function_context):

        if not isinstance(function_context, DIE.Lib.DIEDb.dbFunction_Context):
            if function_context is not None:
                raise ValueError("Wrong value sent to 'on_exclude_ea': %s. excpected dbFunction_Context" % function_context.__class__)
            else:
                raise ValueError("Wrong value sent to 'on_exclude_ea'")

        self.bp_handler.add_bp_ea_exception(function_context.calling_ea)
        return

    @QtCore.Slot(str)
    def on_exclude_library(self, function):

        if not isinstance(function, DIE.Lib.DIEDb.dbFunction):
            if function is not None:
                raise ValueError("Wrong value sent to 'on_exclude_func_adrs': %s. excpected dbFunction_Context" % function.__class__)
            else:
                raise ValueError("Wrong value sent to 'on_exclude_func_adrs'")

        if function.is_lib_func and function.lib_name is not None:
            self.bp_handler.add_module_exception(function.lib_name)

        return

    @QtCore.Slot(str)
    def on_value_detail(self, value):
        if not self.value_view.isVisible():
            self.value_view.Show()

        self.value_view.find_value(value)
        return

    def on_thread_combobox_change(self, thread_id):

        self.reset_function_count(thread_id)  # reset function count according to currently selected thread
        if thread_id == "All Threads":
            if not self.functionTreeView.model() is self.functionModel:
                self.functionTreeView.setModel(self.functionModel)
            return

        hidden_threads = ".*" + self._make_thread_id_data(thread_id) + ".*"

        threadProxyModel = QtGui.QSortFilterProxyModel()
        threadProxyModel.setFilterRole(DIE.UI.ThreadId_Role)
        threadProxyModel.setFilterRegExp(hidden_threads)

        threadProxyModel.setSourceModel(self.functionModel)
        self.functionTreeView.setModel(threadProxyModel)

    def on_valueview_button(self):

        value_view = DIE.UI.ValueViewEx.get_view()
        value_view.Show()

    def on_pluginsview_button(self):

        plugins_view = DIE.UI.ParserView.get_view()
        plugins_view.Show()

    def on_bpview_button(self):

        bp_view = DIE.UI.BPView.get_view()
        bp_view.Show()






















###############################################################################################
#  View Delegates.
#
###############################################################################################

class TreeViewDelegate(QtGui.QStyledItemDelegate):
    """
    Delegate for parsed value viewing in the tree view
    """

    def __init__(self, parent):
        QtGui.QStyledItemDelegate.__init__(self, parent)
        self.parent = parent

    def createEditor(self, parent, option, index):

        parsed_val_list = index.data(role=DIE.UI.ParsedValuesRole)

        # Show combobox only if parsed_value as two or more items.
        if parsed_val_list is not None and len(parsed_val_list) > 1:
            lines = []
            for parsed_val in parsed_val_list:
                line_txt = "%d, %s, %s" % (parsed_val.score, parsed_val.data, parsed_val.description)
                lines.append(line_txt)

            combo_box = QtGui.QComboBox(parent)
            combo_box.addItems(lines)

            return combo_box

    def setEditorData(self, editor, index):

            editor.blockSignals(True)
            editor.setCurrentIndex(int(index.model().data(index)))
            editor.blockSignals(False)

    #
    # This does not seem to work, working on that with some weird guys that actually understand QT.
    #

    # def paint(self, painter, option, index):
    #
    #     parsed_val_list = index.data(role=UI.ParsedValuesRole)
    #     if parsed_val_list is not None and len(parsed_val_list) > 0:
    #         combo_opt = QtGui.QStyleOptionComboBox()
    #         combo_opt.rect = option.rect
    #         combo_opt.state = QtGui.QStyle.State_Enabled
    #         combo_opt.frame = True
    #         combo_opt.currentText = parsed_val_list[0].data
    #
    #         QtCore.QApplication.style().drawComplexControl(QtGui.Qstyle.CC_ComboBox, combo_opt, painter, QtGui.QTreview())
    #
    #         #QtCore.QApplication.style().drawControl(QtGui.Qstyle.CC_ComboBox, combo_opt, painter)
    #         #QtGui.QStyle.drawComplexControl(QtGui.Qstyle.CC_ComboBox, combo_opt, painter)
    #
    #     else:
    #         QtGui.QStyledItemDelegate.paint(self, painter, option, index)
    #
    # def sizeHint(self, option, index):
    #
    #     parsed_val_list = index.data(role=UI.ParsedValuesRole)
    #     max_str = ""
    #     if parsed_val_list is not None and len(parsed_val_list) > 0:
    #         for parsed_val in parsed_val_list:
    #             if len(parsed_val.data) > len(max_str):
    #                 max_str = parsed_val.data
    #
    #     nameFont = QtGui.QFont(option.font)
    #     nameFM = QtGui.QFontMetrics(nameFont)
    #     name_width = nameFM.width(max_str)
    #     name_height = nameFM.height()
    #
    #     return QtCore.QSize(name_width, name_height)




# Singelton
function_view = FunctionView()

def get_view():
    return function_view