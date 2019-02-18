import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.externals import joblib
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import RepeatedKFold
from sklearn.metrics import confusion_matrix


T = 3  # number of performing cross validations
Q = 5  # number of folds
# SCORING = 'accuracy'


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


def make_plot(accuracies, deviations, max_depth, estimators_numbers):
    assert(len(accuracies) == len(deviations))
    plt.figure(figsize=(20, 12))

    upper = []
    lower = []
    for i in range(len(accuracies)):
        upper.append(accuracies[i] + deviations[i])
        lower.append(accuracies[i] - deviations[i])
    plt.fill_between(
        estimators_numbers,
        upper,
        lower,
        alpha=0.2,
        color='steelblue',
        lw=1
    )

    # plt.grid(True)
    plt.xscale('log')
    plt.ylim([0.80, 1.00])
    plt.xlabel('Число деревьев', fontsize=40)
    plt.ylabel('accuracy', fontsize=40)
    ax = plt.gca()
    ax.tick_params(axis='both', which='major', labelsize=40)
    ax.tick_params(axis='both', which='minor', labelsize=40)
    plt.plot(estimators_numbers, accuracies, color='blue', marker='o')
    plt.savefig(
        '../../results/boosting/max_depth{0}.svg'.format(max_depth),
        format='svg',
        dpi=72
    )


def choose_max_depth(X_train, y_train):
    estimators_numbers = (
        50, 100, 250, 500, 1000, 2500, 5000, 10000, 15000, 20000, 25000
    )
    best_accuracy = 0.0
    max_depth = int(sys.argv[1])
    accuracies = []
    deviations = []
    path_to_output_file = '../../results/boosting/{0}.txt'.format(max_depth)
    with open(path_to_output_file, 'w') as output_file:
        for curr_estimators_number in estimators_numbers:
            curr_boost_classifier = GradientBoostingClassifier(
                loss='exponential',
                max_depth=max_depth,
                n_estimators=curr_estimators_number,
                max_features=None
            )
            curr_tns_df, curr_fps_df, curr_fns_df, curr_tps_df = (
                test_classifier(curr_boost_classifier, X_train, y_train)
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
                'max_depth = {0} ; n_estimators = {1} ; accuracy = {2}'.format(
                max_depth, curr_estimators_number, curr_avg_accuracy)
            )
            output_file.write(
                'max_depth = {0} ; n_estimators = {1} ; accuracy = {2}\n'.format(
                max_depth, curr_estimators_number, curr_avg_accuracy)
            )
            if curr_avg_accuracy > best_accuracy:
                best_accuracy = curr_avg_accuracy

        make_plot(accuracies, deviations, max_depth, estimators_numbers)
        output_file.write('\n================================\n')
        output_file.write('best_accuracy = {0}\n'.format(best_accuracy))


def main():
    print('\n****************************************************************')
    print('* Process started with max_depth =', sys.argv[1])
    print('****************************************************************\n')

    X_train = joblib.load('../../data/X_train.pkl')
    y_train = joblib.load('../../data/y_train.pkl')

    # X_train = joblib.load('../../tmp/1467_X_train.pkl')
    # y_train = joblib.load('../../tmp/1467_y_train.pkl')

    choose_max_depth(X_train, y_train)

    print('\n****************************************************************')
    print('* Process finished with max_depth =', sys.argv[1])
    print('****************************************************************\n')


if __name__ == '__main__':
    main()


