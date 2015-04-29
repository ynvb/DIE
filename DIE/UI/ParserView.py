from DIE.Lib import DataParser
from idaapi import PluginForm
from PySide import QtGui, QtCore


class ParserView(PluginForm):
    """
    DIE Value View
    """
    def __init__(self):

        super(ParserView, self).__init__()
        self.data_parser = None
        self.ptable_widget = None

    def Show(self):

        return PluginForm.Show(self,
                               "Parser View",
                               options=PluginForm.FORM_PERSIST)
    def OnCreate(self, form):
        """
        Called when the view is created
        """
        self.data_parser = DataParser.getParser()
        self.ptable_widget = QtGui.QTreeWidget()

        # Get parent widget
        self.parent = self.FormToPySideWidget(form)

        self._add_parser_data()

        layout = QtGui.QGridLayout()
        layout.addWidget(self.ptable_widget)

        self.parent.setLayout(layout)

    def _add_parser_data(self):
        """
        Add parser data to the parser widget model
        @return:
        """
        row = 0
        parser_list = self.data_parser.get_parser_list()
        if not "headers" in parser_list:
            return

        header_list = parser_list["headers"]
        header_list.insert(0, "Plugin Name")

        del parser_list["headers"]  # Remove headers item

        self.ptable_widget.setHeaderLabels(header_list)

        self.ptable_widget.setColumnWidth(0, 200)
        self.ptable_widget.setColumnWidth(1, 500)
        self.ptable_widget.setColumnWidth(2, 80)
        self.ptable_widget.setColumnWidth(3, 80)
        self.ptable_widget.setColumnWidth(4, 200)

        root_item = self.ptable_widget.invisibleRootItem()

        for parser in parser_list:
            current_row_item = QtGui.QTreeWidgetItem()
            current_row_item.setFlags(QtCore.Qt.ItemIsEnabled)
            current_row_item.setText(0, parser)

            num_columns = len(parser_list[parser])
            for column in xrange(0, num_columns):
                currext_text = str(parser_list[parser][column])
                current_row_item.setText(column+1, currext_text)

            root_item.insertChild(row, current_row_item)
            row +=1



_parser_view = None
def initialize():
    global _parser_view
    _parser_view = ParserView()

def get_view():
    return _parser_view
