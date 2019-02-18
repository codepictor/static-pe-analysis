import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.externals import joblib
from sklearn.model_selection import RepeatedKFold
from sklearn.metrics import confusion_matrix
from sklearn.svm import LinearSVC


T = 3  # number of performing cross validations
Q = 5  # number of folds
SCORING = 'accuracy'


X_train = joblib.load('../data/X_train.pkl')
y_train = joblib.load('../data/y_train.pkl')


def test_classifier(classifier, X, y):
    tns, fps, fns, tps = ([], [], [], [])

    rkf = RepeatedKFold(n_splits=Q, n_repeats=T, random_state=398)
    for train_index, test_index in rkf.split(X):
        curr_X_train, curr_X_test = X.iloc[train_index], X.iloc[test_index]
        curr_y_train, curr_y_test = y.iloc[train_index], y.iloc[test_index]
        classifier.fit(curr_X_train, curr_y_train)
        curr_y_pred = classifier.predict(curr_X_test)
        curr_tn, curr_fp, curr_fn, curr_tp = (
            confusion_matrix(curr_y_test, curr_y_pred).ravel()
        )

        curr_test_size = curr_tn + curr_fp + curr_fn + curr_tp
        assert(curr_test_size == len(curr_X_test)
                   and curr_test_size == len(curr_y_test))
        tns.append({
            'tn': curr_tn,
            'test_size': curr_test_size,
            'tn_rate': curr_tn/curr_test_size,
        })
        fps.append({
            'fp': curr_fp,
            'test_size': curr_test_size,
            'fp_rate': curr_fp/curr_test_size,
        })
        fns.append({
            'fn': curr_fn,
            'test_size': curr_test_size,
            'fn_rate': curr_fn/curr_test_size,
        })
        tps.append({
            'tp': curr_tp,
            'test_size': curr_test_size,
            'tp_rate': curr_tp/curr_test_size,
        })

    tns_df = pd.DataFrame(tns)
    fps_df = pd.DataFrame(fps)
    fns_df = pd.DataFrame(fns)
    tps_df = pd.DataFrame(tps)
    return (tns_df, fps_df, fns_df, tps_df)


def make_plot(accuracies, deviations, C_tuple, kernel):
    assert(len(accuracies) == len(deviations))
    plt.figure(figsize=(20, 12))

    upper = []
    lower = []
    for i in range(len(accuracies)):
        upper.append(accuracies[i] + deviations[i])
        lower.append(accuracies[i] - deviations[i])
    plt.fill_between(
        C_tuple,
        upper,
        lower,
        alpha=0.2,
        color='steelblue',
        lw=1
    )

    # plt.grid(True)
    plt.xscale('log')
    plt.ylim([0.50, 1.00])
    plt.xlabel('C', fontsize=32)
    plt.ylabel(SCORING, fontsize=32)
    ax = plt.gca()
    ax.tick_params(axis='both', which='major', labelsize=32)
    ax.tick_params(axis='both', which='minor', labelsize=32)
    plt.plot(C_tuple, accuracies, color='blue', marker='o')
    plt.savefig(
        '../results/svm/kernels/{0}.svg'.format(kernel),
        format='svg',
        dpi=72
    )


def choose_hyperparameters(X_train, y_train):
    C_tuple = (0.01, 0.05, 0.1, 0.5, 1, 5, 10, 50, 100, 500, 1000, 5000, 1e4, 5e4, 1e5)
    kernels = ('linear',)

    for curr_kernel in kernels:
        accuracies = []
        deviations = []
        for curr_C in C_tuple:
            curr_svm_classifier = LinearSVC(
                dual=False,
                C=curr_C
            )
            curr_tns_df, curr_fps_df, curr_fns_df, curr_tps_df = (
                test_classifier(curr_svm_classifier, X_train, y_train)
            )

            curr_accuracies = []
            for i in range(T*Q):
                curr_tn_rate = curr_tns_df.at[i, 'tn_rate']
                curr_fp_rate = curr_fps_df.at[i, 'fp_rate']
                curr_fn_rate = curr_fns_df.at[i, 'fn_rate']
                curr_tp_rate = curr_tps_df.at[i, 'tp_rate']
                curr_accuracies.append(
                    (curr_tp_rate + curr_tn_rate)/
                    (curr_tp_rate + curr_tn_rate + curr_fp_rate + curr_fn_rate)
                )
            curr_avg_accuracy = sum(curr_accuracies)/len(curr_accuracies)
            accuracies.append(curr_avg_accuracy)
            deviations.append(np.array(curr_accuracies).std()*2)
            print(
                'curr_C =', curr_C,
                '; curr_avg_accuracy =', curr_avg_accuracy,
                '; curr_kernel =', curr_kernel
            )
        make_plot(accuracies, deviations, C_tuple, curr_kernel)


choose_hyperparameters(X_train, y_train)


