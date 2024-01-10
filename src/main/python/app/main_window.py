import os
import os.path
import time

from PySide2.QtCore import QThread, QSize
from PySide2.QtGui import QTextCursor, Qt
from PySide2.QtWidgets import (
    QMainWindow,
    QFileDialog,
    QMessageBox,
    QTableWidgetItem,
    # QWidget,
    # QLabel,
    # QHBoxLayout,
    QAbstractItemView,
    QApplication,
    QStyle
)

from .ui_main_window import Ui_MainWindow
from .worker import Worker
from pe import pe_utils
from pe import static_pe_analyzer


class MainWindow(QMainWindow, Ui_MainWindow):
    """"""

    def __init__(self, ctx):
        super().__init__()

        self.ctx = ctx

        # self._ui = Ui_MainWindow()
        # self._ui.setupUi(self)
        self.setupUi(self)
        self.set_up_ui()

        self._thread = QThread()
        self._worker = None

        self._positive_predictions = []
        self._unpredicted_files_n = 0
        self._scanned_files_n = 0
        self._start_timestamp = time.time()

    def validate(self):
        """"""
        pass

    def set_up_ui(self):
        """"""
        self.setWindowTitle('Static-PE-Analyzer')
        # self.ui.setWindowIcon(self.ctx.img_logo)

        self.action_OpenFile.triggered.connect(self.open_file)
        self.action_OpenDir.triggered.connect(self.open_dir)
        self.action_Quit.triggered.connect(self.on_actionExit_triggered)
        self.action_About.triggered.connect(self.on_actionAbout_triggered)

        self.action_About.setIcon(
            self.style().standardIcon(QStyle.SP_MessageBoxQuestion)
        )

        self.pushButton_OpenFile.clicked.connect(self.open_file)
        self.pushButton_OpenDir.clicked.connect(self.open_dir)

        self.pushButton_RunModel.setEnabled(False)
        self.pushButton_RunModel.clicked.connect(self.run_model)
        self.pushButton_StopModel.setEnabled(False)
        self.pushButton_StopModel.clicked.connect(self.stop_model)

        self.tableWidget_Results.setColumnWidth(0, 500)
        self.tableWidget_Results.setColumnWidth(1, 100)
        self.tableWidget_Results.setColumnWidth(2, 100)
        self.tableWidget_Results.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        # header_view = QHeaderView(Qt.Horizontal, self.ui.tableWidget_Results)
        # header_view.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        # header_view.setSectionResizeMode(1, QHeaderView.Fixed)
        # header_view.setSectionResizeMode(2, QHeaderView.Fixed)
        # self.tableWidget_Results.setHorizontalHeader(header_view)

        self.statusbar.showMessage(
            'Choose a PE file or a directory containing PE files...'
        )

        # self.pushButton_RandomNumber.clicked.connect(
        #     self.generate_random_number
        # )

    # def generate_random_number(self):
    #     """"""
    #     print('Pressed!')
    #     self.label_RandomNumber.setText(
    #         str(random.randint(0, 100))
    #     )

    def open_file(self):
        """"""
        path_to_file, _ = QFileDialog.getOpenFileName(
            self,
            "Open File"
            # "(*.exe *.dll)",
            # "(*.exe)",
            # options=QFileDialog.DontUseNativeDialog
        )
        if path_to_file:
            if pe_utils.is_pe_file(path_to_file):
                self.prepare_run(path_to_file)
                return
            else:
                QMessageBox.about(
                    self,
                    'Information',
                    'The selected file is not recognized as PE file.'
                )
        self.cancel_run()

    def open_dir(self):
        """"""
        path_to_dir = QFileDialog.getExistingDirectory(
            self,
            "Open Directory"
        )
        if path_to_dir:
            self.prepare_run(path_to_dir)
        else:
            self.cancel_run()

    def prepare_run(self, path_to_file_or_dir):
        """"""
        if path_to_file_or_dir:
            self.pushButton_RunModel.setEnabled(True)
            self.label_Path.setText(path_to_file_or_dir)
            # font_metrics = self.label_Path.fontMetrics()
            # elided_text = font_metrics.elidedText(
            #     path_to_file_or_dir, Qt.ElideRight, self.label_Path.width()
            # )
            # self.label_Path.setText(elided_text)

    def cancel_run(self):
        """"""
        self.label_Path.setText('')
        self.pushButton_RunModel.setEnabled(False)

    def start_run(self):
        """"""
        self._positive_predictions.clear()
        self._unpredicted_files_n = 0
        self._scanned_files_n = 0
        self._start_timestamp = time.time()

        self.pushButton_OpenFile.setEnabled(False)
        self.pushButton_OpenDir.setEnabled(False)
        self.pushButton_RunModel.setEnabled(False)
        self.pushButton_StopModel.setEnabled(True)

        self.tableWidget_Results.clearContents()
        self.tableWidget_Results.setRowCount(0)
        self.tableWidget_Results.setSortingEnabled(False)

        self.plainTextEdit_Results.clear()
        self.plainTextEdit_Results.insertPlainText('Starting...\n')
        self.plainTextEdit_Results.moveCursor(QTextCursor.End)

        self.statusbar.showMessage('Starting...')

    def run_model(self):
        """"""
        self.validate()

        label_path = self.label_Path.text()

        if os.path.isfile(label_path) or os.path.isdir(label_path):
            self.start_run()
            paths_to_pe_files = static_pe_analyzer.get_paths_to_pe_files(
                label_path
            )

            self._thread.deleteLater()
            self._thread = QThread()
            self._worker = Worker(paths_to_pe_files, self.ctx.clf)
            self._worker.moveToThread(self._thread)

            self._thread.started.connect(self._worker.run)
            self._worker.finished.connect(self._thread.quit)
            self._worker.finished.connect(self._worker.deleteLater)
            # self._thread.finished.connect(self._thread.deleteLater)
            self._worker.progress.connect(self.add_row)

            self._thread.finished.connect(self.finish_run)

            self._thread.start()

        else:
            QMessageBox.about(
                self,
                'Error',
                'The selected path is neither a file nor a directory.'
            )

    def stop_model(self):
        """"""
        # if self._thread is not None:
        self._thread.requestInterruption()
        self.pushButton_StopModel.setEnabled(False)
        self.plainTextEdit_Results.insertPlainText('Stopping...\n')
        self.plainTextEdit_Results.moveCursor(QTextCursor.End)

    def finish_run(self):
        """"""
        self.plainTextEdit_Results.insertPlainText(
            '\n*********************************************************\n'
        )
        self.plainTextEdit_Results.moveCursor(QTextCursor.End)
        self.plainTextEdit_Results.insertPlainText(
            '\nUNUSUAL FILES: {}\n'.format(len(self._positive_predictions))
        )
        self.plainTextEdit_Results.moveCursor(QTextCursor.End)
        for positive_prediction in self._positive_predictions:
            self.plainTextEdit_Results.insertPlainText(
                '"{0}" : SCORE = {1}\n'.format(
                    positive_prediction['path_to_file'],
                    positive_prediction['score']
                )
            )
            self.plainTextEdit_Results.moveCursor(QTextCursor.End)

        self.plainTextEdit_Results.insertPlainText(
            'FILES WITHOUT PREDICTION: {}\n'.format(
                self._unpredicted_files_n
            )
        )
        self.plainTextEdit_Results.moveCursor(QTextCursor.End)

        self.plainTextEdit_Results.insertPlainText(
            'TOTAL FILES SCANNED: {}\n'.format(
                self._scanned_files_n
            )
        )
        self.plainTextEdit_Results.moveCursor(QTextCursor.End)

        self.plainTextEdit_Results.insertPlainText(
            'ELAPSED TIME: {:.2f} seconds\n'.format(
                time.time() - self._start_timestamp
            )
        )
        self.plainTextEdit_Results.moveCursor(QTextCursor.End)

        self.pushButton_OpenFile.setEnabled(True)
        self.pushButton_OpenDir.setEnabled(True)
        self.pushButton_RunModel.setEnabled(True)
        self.pushButton_StopModel.setEnabled(False)

        self.tableWidget_Results.setSortingEnabled(True)
        self.tableWidget_Results.update()

        self.plainTextEdit_Results.insertPlainText('Done.\n')
        self.plainTextEdit_Results.moveCursor(QTextCursor.End)
        self.plainTextEdit_Results.update()

        self.statusbar.showMessage('Done')

        QMessageBox.about(
            self,
            'Finished!',
            'The final report is ready.'
        )

    def add_row(self, row_idx, prediction):
        """"""
        if prediction['label'] is not None:
            if prediction['label']:
                self._positive_predictions.append(prediction)
        else:
            self._unpredicted_files_n += 1
        self._scanned_files_n += 1

        self.tableWidget_Results.insertRow(row_idx)

        self.tableWidget_Results.setItem(
            row_idx, 0, QTableWidgetItem(prediction['path_to_file'])
        )

        icon_item = self.get_icon_item(prediction['label'])
        self.tableWidget_Results.setItem(
            row_idx, 1, icon_item
        )
        # self.set_table_icon(row_idx, prediction['label'])

        if prediction['score'] is not None:
            score_item = QTableWidgetItem()
            score_item.setText('{:.2f}'.format(prediction['score']))
            score_item.setData(Qt.DisplayRole, prediction['score'])
            score_item.setTextAlignment(Qt.AlignCenter)
            self.tableWidget_Results.setItem(
                row_idx, 2, score_item
            )

        self.tableWidget_Results.setItem(
            row_idx, 3, QTableWidgetItem(prediction['note'])
        )

        log_row = prediction['path_to_file'] + ': '
        if prediction['label'] is None:
            log_row += 'NO PREDICTION'
        else:
            if prediction['label']:
                log_row += 'WARNING'
            else:
                log_row += 'OK'
            assert prediction['score'] is not None
            log_row += '; SCORE = {:.2f}'.format(prediction['score'])

        log_row += '; NOTE: ' + prediction['note'] + '\n'

        self.plainTextEdit_Results.insertPlainText(log_row)
        self.plainTextEdit_Results.moveCursor(QTextCursor.End)
        self.statusbar.showMessage(log_row)

    def get_icon_item(self, predicted_label):
        """"""
        icon_item = QTableWidgetItem()
        icon_item.setTextAlignment(Qt.AlignCenter)

        if predicted_label is None:
            # icon_item.setData(Qt.DisplayRole, 0.0)
            # icon_item.setIcon(self.ctx.img_no_result)
            icon_item.setIcon(
                self.style().standardIcon(QStyle.SP_MessageBoxQuestion)
            )
            return icon_item

        if predicted_label:
            # icon_item.setIcon(self.ctx.img_warning)
            # icon_item.setData(Qt.DisplayRole, 1.0)
            icon_item.setIcon(
                self.style().standardIcon(QStyle.SP_MessageBoxWarning)
            )
        else:
            # icon_item.setData(Qt.DisplayRole, -1.0)
            icon_item.setIcon(self.ctx.img_ok)

        return icon_item

    # def get_table_icon(self, predicted_label):
    #     """"""
    #     assert predicted_label is None or predicted_label in [True, False]
    #
    #     if predicted_label is None:
    #         return self.ctx.img_no_result
    #
    #     if predicted_label:
    #         return self.style().standardIcon(QStyle.SP_MessageBoxWarning)
    #
    #     return self.ctx.img_ok

    # def set_table_icon(self, row_idx, predicted_label):
    #     """"""
    #     assert row_idx >= 0
    #     assert predicted_label is None or predicted_label in [True, False]
    #
    #     icon = self.get_table_icon(predicted_label)
    #     icon_size = QSize(16, 16)
    #
    #     icon_label = QLabel()
    #     icon_label.setMaximumSize(icon_size)
    #     icon_label.setScaledContents(True)
    #     icon_label.setPixmap(icon.pixmap(icon_size))
    #
    #     icon_widget = QWidget()
    #     icon_layout = QHBoxLayout(icon_widget)
    #     icon_layout.addWidget(icon_label)
    #     icon_layout.setAlignment(Qt.AlignCenter)
    #     icon_layout.setContentsMargins(0, 0, 0, 0)
    #     icon_widget.setLayout(icon_layout)
    #
    #     self.tableWidget_Results.setCellWidget(row_idx, 1, icon_widget)

    def closeEvent(self, event):
        """"""
        self._thread.requestInterruption()
        event.accept()

    def on_actionExit_triggered(self):
        """"""
        self._thread.requestInterruption()
        QApplication.quit()

    def on_actionAbout_triggered(self):
        """"""
        msg = 'Static PE Analyzer.\n\n'

        msg += (
            'This tool is designed to search for potentially malicious '
            'code inside PE files (now only .exe is supported) '
            'with the help of static ML analysis. '
            'The word "static" means that these files are not run, '
            'so the code inside these PE files will not be executed. '
            'Instead, a PE file is parsed, '
            'and some features are extracted from its layout. '
            'These features are fed to the machine learning model to get '
            'a score for this PE file. '
            'If the score is negative, a file is considered to be safe. '
            'The higher this score, the more dangerous the file is.\n\n'
        )

        msg += (
            'We appreciate your interest in our software. '
            'While we strive to provide a reliable and effective tool, '
            'we want to emphasize that the use of this software is at your own risk. '
            'The authors of the software cannot be responsible '
            'for any outcomes or consequences resulting from its use.\n\n'
        )

        msg += (
            'Please ensure that you understand the capabilities and '
            'limitations of the software before utilizing it for any purpose.\n\n'
        )

        msg += (
            'Thank you for your understanding.\n'
        )

        QMessageBox.about(
            self,
            'About Static PE Analyzer',
            msg
        )
