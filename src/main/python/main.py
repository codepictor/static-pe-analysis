import sys

# from PySide2 import QtCore

from app_context import AppContext


def main():
    # QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)

    appctxt = AppContext()
    exit_code = appctxt.run()

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
