# import multiprocessing

from PySide2.QtCore import QObject, QThread, Signal

from pe import static_pe_analyzer


# import pefile
# import numpy as np
# from sklearn.neighbors import KNeighborsRegressor


# def _get_prediction(path_to_pe_file, clf, return_dict):
#     try:
#         prediction = static_pe_analyzer.get_prediction(
#             path_to_pe_file, clf
#         )
#         # return_dict['predicted_label'] = prediction[0]
#         # return_dict['predicted_score'] = prediction[1]
#         # return_dict['exception_text'] = ''
#         return prediction[0], prediction[1], ''
#     except Exception as e:
#         # return_dict['predicted_label'] = None
#         # return_dict['predicted_score'] = None
#         # return_dict['exception_text'] = str(e)
#         return None, None, str(e)


# def _get_prediction(path_to_pe_file):
#     predicted_label = None
#     predicted_score = 0.0
#
#     # try:
#     #     for _ in range(100000000):
#     #         predicted_score += 0.000001
#     # except Exception as e:
#     #     pass
#
#     # res = pefile.PE(path_to_pe_file)
#
#     # fd = open(path_to_pe_file, "rb")
#     #
#     # fileno = fd.fileno()
#     #
#     # if hasattr(mmap, "MAP_PRIVATE"):
#     #     # Unix
#     #     data = mmap.mmap(fileno, 0, mmap.MAP_PRIVATE)
#     # else:
#     #     # Windows
#     #     data = mmap.mmap(fileno, 0, access=mmap.ACCESS_READ)
#     #
#     # print(len(data))
#     # fd.close()
#
#     # X_train = np.random.rand(10000, 25)
#     # y_train = np.random.rand(10000)
#     # model = KNeighborsRegressor().fit(X_train, y_train)
#     # y_pred = model.predict(X_train + 0.15)
#     #
#     # predicted_score = np.mean(y_pred)
#     # print(predicted_score)
#
#     return predicted_label, predicted_score


# def _get_predictions(paths_to_pe_files, clf, queue_in, queue_out):
#     assert clf is not None
#
#     for path_to_pe_file in paths_to_pe_files:
#         if not queue_in.empty():
#             msg = queue_in.get()
#             assert msg is None and queue_in.empty()
#             queue_out.put(None)
#             return
#
#         try:
#             prediction = static_pe_analyzer.get_prediction(
#                 path_to_pe_file, clf
#             )
#             res = path_to_pe_file, prediction[0], prediction[1], ''
#             queue_out.put(res)
#         except Exception as e:
#             res = path_to_pe_file, None, None, str(e)
#             queue_out.put(res)
#
#     queue_out.put(None)


class Worker(QObject):
    """"""

    # pe_file_idx, prediction
    progress = Signal(int, dict)
    finished = Signal()

    def __init__(self, paths_to_pe_files, clf):
        super().__init__()

        self.paths_to_pe_files = paths_to_pe_files
        self.clf = clf

    def run(self):
        """"""
        row_idx = 0

        for path_to_pe_file in self.paths_to_pe_files:
            if QThread.currentThread().isInterruptionRequested():
                self.finished.emit()
                return

            try:
                prediction = static_pe_analyzer.get_prediction(
                    path_to_pe_file, self.clf
                )
                assert len(prediction) == 4
                self.progress.emit(row_idx, prediction)
            except Exception as e:
                self.progress.emit(
                    row_idx,
                    {
                        'path_to_file': path_to_pe_file,
                        'label': None,
                        'proba': None,
                        'score': None,
                        'note': str(e)
                    }
                )

            row_idx += 1

        self.finished.emit()

    # def _run(self):
    #     row_idx = 0
    #
    #     q_in = multiprocessing.Queue()
    #     q_out = multiprocessing.Queue()
    #
    #     p = multiprocessing.Process(
    #         target=_get_predictions,
    #         args=(self.paths_to_pe_files, self.clf, q_in, q_out)
    #     )
    #     p.start()
    #
    #     while not QThread.currentThread().isInterruptionRequested():
    #         res = q_out.get()
    #
    #         if res is None:
    #             p.join()
    #             self.finished.emit()
    #             return
    #
    #         assert len(res) == 4
    #         # print('#####', res)
    #         self.progress.emit(row_idx, res[0], res[1], res[2], res[3])
    #         row_idx += 1
    #
    #     q_in.put(None)
    #     p.join()
    #     # print('Subprocess finished!')
    #     self.finished.emit()
