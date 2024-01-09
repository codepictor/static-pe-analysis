# from pathlib import Path

from PySide2.QtGui import QIcon
from sklearn.externals import joblib
from fbs_runtime.application_context.PySide2 import ApplicationContext
from fbs_runtime.application_context.PySide2 import cached_property

from app.main_window import MainWindow


class AppContext(ApplicationContext):

    def run(self):
        # self.app.setStyleSheet(Path(self.stylesheet).read_text())
        self.main_window.show()
        return self.app.exec_()

    @cached_property
    def main_window(self):
        return MainWindow(self)

    # @cached_property
    # def stylesheet(self):
    #     return self.get_resource('')

    # @cached_property
    # def main_window_ui(self):
    #     return QUiLoader().load(
    #         self.get_resource('ui/main_window.ui'),
    #         None
    #     )

    @cached_property
    def clf(self):
        return joblib.load(
            self.get_resource('model/boosting_classifier.pkl')
        )

    @cached_property
    def img_ok(self):
        return QIcon(self.get_resource('images/ok.png'))

    # @cached_property
    # def img_warning(self):
    #     return QIcon(self.get_resource('images/warning.png'))

    # @cached_property
    # def img_no_result(self):
    #     return QIcon(self.get_resource('images/no_result.png'))

    # @cached_property
    # def img_logo(self):
    #     return QIcon(self.get_resource('images/logo.png'))
