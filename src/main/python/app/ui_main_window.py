# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'main_window.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(800, 600)
        MainWindow.setMinimumSize(QSize(800, 600))
        self.action_OpenFile = QAction(MainWindow)
        self.action_OpenFile.setObjectName(u"action_OpenFile")
        self.action_OpenDir = QAction(MainWindow)
        self.action_OpenDir.setObjectName(u"action_OpenDir")
        self.action_Quit = QAction(MainWindow)
        self.action_Quit.setObjectName(u"action_Quit")
        self.action_About = QAction(MainWindow)
        self.action_About.setObjectName(u"action_About")
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.verticalLayout = QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.label_Info = QLabel(self.centralwidget)
        self.label_Info.setObjectName(u"label_Info")
        self.label_Info.setEnabled(True)

        self.horizontalLayout_2.addWidget(self.label_Info)

        self.pushButton_OpenFile = QPushButton(self.centralwidget)
        self.pushButton_OpenFile.setObjectName(u"pushButton_OpenFile")
        self.pushButton_OpenFile.setMaximumSize(QSize(180, 16777215))

        self.horizontalLayout_2.addWidget(self.pushButton_OpenFile)

        self.pushButton_OpenDir = QPushButton(self.centralwidget)
        self.pushButton_OpenDir.setObjectName(u"pushButton_OpenDir")
        self.pushButton_OpenDir.setMaximumSize(QSize(180, 16777215))
        self.pushButton_OpenDir.setCheckable(False)
        self.pushButton_OpenDir.setChecked(False)

        self.horizontalLayout_2.addWidget(self.pushButton_OpenDir)


        self.verticalLayout.addLayout(self.horizontalLayout_2)

        self.horizontalLayout_4 = QHBoxLayout()
        self.horizontalLayout_4.setObjectName(u"horizontalLayout_4")
        self.label_Selected = QLabel(self.centralwidget)
        self.label_Selected.setObjectName(u"label_Selected")
        self.label_Selected.setMaximumSize(QSize(100, 16777215))

        self.horizontalLayout_4.addWidget(self.label_Selected)

        self.label_Path = QLabel(self.centralwidget)
        self.label_Path.setObjectName(u"label_Path")

        self.horizontalLayout_4.addWidget(self.label_Path)

        self.pushButton_RunModel = QPushButton(self.centralwidget)
        self.pushButton_RunModel.setObjectName(u"pushButton_RunModel")
        self.pushButton_RunModel.setMinimumSize(QSize(180, 0))
        self.pushButton_RunModel.setMaximumSize(QSize(180, 16777215))

        self.horizontalLayout_4.addWidget(self.pushButton_RunModel)

        self.pushButton_StopModel = QPushButton(self.centralwidget)
        self.pushButton_StopModel.setObjectName(u"pushButton_StopModel")
        self.pushButton_StopModel.setMinimumSize(QSize(180, 0))
        self.pushButton_StopModel.setMaximumSize(QSize(180, 16777215))

        self.horizontalLayout_4.addWidget(self.pushButton_StopModel)


        self.verticalLayout.addLayout(self.horizontalLayout_4)

        self.line = QFrame(self.centralwidget)
        self.line.setObjectName(u"line")
        self.line.setFrameShape(QFrame.HLine)
        self.line.setFrameShadow(QFrame.Sunken)

        self.verticalLayout.addWidget(self.line)

        self.horizontalLayout_5 = QHBoxLayout()
        self.horizontalLayout_5.setObjectName(u"horizontalLayout_5")
        self.label_FinalReport = QLabel(self.centralwidget)
        self.label_FinalReport.setObjectName(u"label_FinalReport")
        self.label_FinalReport.setMaximumSize(QSize(90, 16777215))

        self.horizontalLayout_5.addWidget(self.label_FinalReport)

        self.label_SpinningWheel = QLabel(self.centralwidget)
        self.label_SpinningWheel.setObjectName(u"label_SpinningWheel")

        self.horizontalLayout_5.addWidget(self.label_SpinningWheel)


        self.verticalLayout.addLayout(self.horizontalLayout_5)

        self.tableWidget_Results = QTableWidget(self.centralwidget)
        if (self.tableWidget_Results.columnCount() < 4):
            self.tableWidget_Results.setColumnCount(4)
        __qtablewidgetitem = QTableWidgetItem()
        __qtablewidgetitem.setTextAlignment(Qt.AlignCenter);
        self.tableWidget_Results.setHorizontalHeaderItem(0, __qtablewidgetitem)
        __qtablewidgetitem1 = QTableWidgetItem()
        __qtablewidgetitem1.setTextAlignment(Qt.AlignCenter);
        self.tableWidget_Results.setHorizontalHeaderItem(1, __qtablewidgetitem1)
        __qtablewidgetitem2 = QTableWidgetItem()
        __qtablewidgetitem2.setTextAlignment(Qt.AlignCenter);
        self.tableWidget_Results.setHorizontalHeaderItem(2, __qtablewidgetitem2)
        __qtablewidgetitem3 = QTableWidgetItem()
        __qtablewidgetitem3.setTextAlignment(Qt.AlignCenter);
        self.tableWidget_Results.setHorizontalHeaderItem(3, __qtablewidgetitem3)
        self.tableWidget_Results.setObjectName(u"tableWidget_Results")
        self.tableWidget_Results.setLayoutDirection(Qt.LeftToRight)
        self.tableWidget_Results.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContentsOnFirstShow)
        self.tableWidget_Results.setSortingEnabled(True)
        self.tableWidget_Results.horizontalHeader().setCascadingSectionResizes(False)
        self.tableWidget_Results.horizontalHeader().setMinimumSectionSize(80)
        self.tableWidget_Results.horizontalHeader().setDefaultSectionSize(80)
        self.tableWidget_Results.horizontalHeader().setHighlightSections(False)
        self.tableWidget_Results.horizontalHeader().setProperty("showSortIndicator", True)
        self.tableWidget_Results.horizontalHeader().setStretchLastSection(True)

        self.verticalLayout.addWidget(self.tableWidget_Results)

        self.label_Logs = QLabel(self.centralwidget)
        self.label_Logs.setObjectName(u"label_Logs")

        self.verticalLayout.addWidget(self.label_Logs)

        self.plainTextEdit_Results = QPlainTextEdit(self.centralwidget)
        self.plainTextEdit_Results.setObjectName(u"plainTextEdit_Results")
        self.plainTextEdit_Results.setMaximumSize(QSize(16777215, 150))
        self.plainTextEdit_Results.setSizeIncrement(QSize(0, 0))
        self.plainTextEdit_Results.setReadOnly(True)

        self.verticalLayout.addWidget(self.plainTextEdit_Results)

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QMenuBar(MainWindow)
        self.menubar.setObjectName(u"menubar")
        self.menubar.setGeometry(QRect(0, 0, 800, 22))
        self.menuFile = QMenu(self.menubar)
        self.menuFile.setObjectName(u"menuFile")
        self.menuHelp = QMenu(self.menubar)
        self.menuHelp.setObjectName(u"menuHelp")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName(u"statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuHelp.menuAction())
        self.menuFile.addAction(self.action_OpenFile)
        self.menuFile.addAction(self.action_OpenDir)
        self.menuFile.addSeparator()
        self.menuFile.addAction(self.action_Quit)
        self.menuHelp.addAction(self.action_About)

        self.retranslateUi(MainWindow)

        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"MainWindow", None))
        self.action_OpenFile.setText(QCoreApplication.translate("MainWindow", u"Open file...", None))
        self.action_OpenDir.setText(QCoreApplication.translate("MainWindow", u"Open dirictory...", None))
        self.action_Quit.setText(QCoreApplication.translate("MainWindow", u"Quit", None))
        self.action_About.setText(QCoreApplication.translate("MainWindow", u"About Static PE Analyzer", None))
        self.label_Info.setText(QCoreApplication.translate("MainWindow", u"Open a file (.exe or .dll) or a directory...", None))
        self.pushButton_OpenFile.setText(QCoreApplication.translate("MainWindow", u"Open a file...", None))
        self.pushButton_OpenDir.setText(QCoreApplication.translate("MainWindow", u"Open a directory...", None))
        self.label_Selected.setText(QCoreApplication.translate("MainWindow", u"Selected path:", None))
        self.label_Path.setText("")
        self.pushButton_RunModel.setText(QCoreApplication.translate("MainWindow", u"Run model", None))
        self.pushButton_StopModel.setText(QCoreApplication.translate("MainWindow", u"Stop", None))
        self.label_FinalReport.setText(QCoreApplication.translate("MainWindow", u"Final report:", None))
        self.label_SpinningWheel.setText("")
        ___qtablewidgetitem = self.tableWidget_Results.horizontalHeaderItem(0)
        ___qtablewidgetitem.setText(QCoreApplication.translate("MainWindow", u"File", None));
        ___qtablewidgetitem1 = self.tableWidget_Results.horizontalHeaderItem(1)
        ___qtablewidgetitem1.setText(QCoreApplication.translate("MainWindow", u"Prediction", None));
        ___qtablewidgetitem2 = self.tableWidget_Results.horizontalHeaderItem(2)
        ___qtablewidgetitem2.setText(QCoreApplication.translate("MainWindow", u"Score", None));
        ___qtablewidgetitem3 = self.tableWidget_Results.horizontalHeaderItem(3)
        ___qtablewidgetitem3.setText(QCoreApplication.translate("MainWindow", u"Note", None));
        self.label_Logs.setText(QCoreApplication.translate("MainWindow", u"Logs:", None))
        self.menuFile.setTitle(QCoreApplication.translate("MainWindow", u"File", None))
        self.menuHelp.setTitle(QCoreApplication.translate("MainWindow", u"Help", None))
    # retranslateUi

