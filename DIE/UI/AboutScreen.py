

from idaapi import Form
import os
import DIE.Lib.DieConfig

from cute import QtCore, QtWidgets, QtGui

class AboutWindow(QtWidgets.QDialog):
    def __init__(self):
        super(AboutWindow, self).__init__()

        self.initUI()

    def initUI(self):
        config = DIE.Lib.DieConfig.get_config()
        self.setFixedSize(400, 330)
        self.setWindowTitle("About DIE")

        image = QtGui.QImage(os.path.join(config.icons_path, "logo.png"))
        pixmap = QtGui.QPixmap.fromImage(image)


        logo = QtWidgets.QLabel(self)
        logo.setFixedSize(pixmap.size())
        logo.move(0.5*(self.width() - logo.width()), 20)
        logo.setPixmap(pixmap)

        title = QtWidgets.QLabel("DIE",self)
        title.setAlignment(QtCore.Qt.AlignCenter)
        font = title.font()
        font.setPointSize(16)
        font.setBold(True)
        title.setFont(font)
        title.setFixedWidth(400)
        title.move(0, logo.height() + logo.y() + 20)

        subtitle = QtWidgets.QLabel("Dynamic IDA Enrichment framework",self)
        font = subtitle.font()
        font.setPointSize(14)
        subtitle.setFont(font)
        subtitle.setAlignment(QtCore.Qt.AlignCenter)
        subtitle.setFixedWidth(400)
        subtitle.move(0, title.height() + title.y() + 10)

        version = QtWidgets.QLabel("Version 0.1",self)
        font = subtitle.font()
        font.setPointSize(12)
        version.setFont(font)
        version.setAlignment(QtCore.Qt.AlignCenter)
        version.setFixedWidth(400)
        version.move(0, subtitle.height() + subtitle.y() + 30)

        author = QtWidgets.QLabel("Written by Yaniv Balmas @ynvb - Check Point Software Technologies",self)
        font = subtitle.font()
        font.setPointSize(12)
        author.setFont(font)
        author.setAlignment(QtCore.Qt.AlignCenter)
        author.setFixedWidth(400)
        author.move(0, version.height() + version.y())



        self.show()
