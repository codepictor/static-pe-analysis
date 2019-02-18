import os
import sys
import math
import pefile
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.externals import joblib
from sklearn.svm import LinearSVC
from sklearn.model_selection import RepeatedKFold
from mlxtend.feature_selection import SequentialFeatureSelector as SFS
from mlxtend.plotting import plot_sequential_feature_selection as plot_sfs

# we perform T*Q-fold cross validation (T*Q-fold CV)
T = 3  # number of performing cross validations
Q = 5  # number of folds
SCORING = 'accuracy'


def find_max_score(subsets):
    best_score = 0.0
    best_features_number = 0
    best_features_subset = None
    for curr_features_number, curr_subset_info in subsets.items():
        curr_score = curr_subset_info['avg_score']
        if curr_score > best_score:
            best_score = curr_score
            best_features_number = curr_features_number
            best_features_subset = curr_subset_info['feature_idx']
    return (best_score, best_features_number, best_features_subset)


def make_plot(sfs, C, is_forward):
    fig = plot_sfs(
        sfs.get_metric_dict(),
        kind='std_dev'
    )

    axes = fig.add_subplot(111)
    a = axes.get_xticks().tolist()
    for i in range(len(a)):
        if i % 5 != 0:
            a[i] = ''
    axes.set_xticklabels(a)
    axes.tick_params(axis='both', which='major', labelsize=40)
    axes.tick_params(axis='both', which='minor', labelsize=40)

    fig.set_size_inches(20, 12, forward=True)
    plt.ylim([0.60, 0.90])
    plt.xlabel('Число признаков', fontsize=40)
    plt.ylabel(SCORING, fontsize=40)
    # plt.title('Последовательный отбор признаков (C = {0})'.format(C))
    # plt.grid(True)
    plt.savefig(
        '../../results/svm/features_selection/'
        + 'svm_C={0}_forward={1}.svg'.format(C, is_forward),
        format='svg',
        dpi=300
    )


def make_debug_info(sfs, C, is_forward):
    path_to_output_file = (
        '../../results/svm/features_selection/'
        + 'svm_C={0}_forward={1}.txt'.format(C, is_forward)
    )
    with open(path_to_output_file, 'w') as output_file:
        output_file.write('C = {0}\n'.format(C))
        output_file.write('is_forward = {0}\n\n\n'.format(is_forward))
        output_file.write('SUBSETS:\n{0}\n\n\n'.format(sfs.subsets_))
        best_params = find_max_score(sfs.subsets_)
        output_file.write(
            'best_score = {0}\n'.format(best_params[0])
        )
        output_file.write(
            'best_features_number = {0}\n'.format(best_params[1])
        )
        output_file.write(
            'best_features_subset = {0}\n\n\n'.format(best_params[2])
        )
        # output_file.write(
        #     'BEST (sfs.k_feature_idx_): {0}\n\n\n'.format(sfs.k_feature_idx_)
        # )


def make_features_selection(X_train, y_train, is_forward):
    curr_C = float(sys.argv[1])

    rkf = RepeatedKFold(n_splits=Q, n_repeats=T)
    features_number = 90 if is_forward else len(X_train.columns) - 12

    curr_svm_classifier = LinearSVC(penalty='l2', dual=False, C=curr_C)
    sfs = SFS(estimator=curr_svm_classifier,
              k_features=features_number,
              forward=is_forward,
              floating=True,
              n_jobs=-1,
              verbose=2,
              scoring=SCORING,
              cv=rkf)
    sfs = sfs.fit(X_train.values, y_train)
    make_plot(sfs, curr_C, is_forward)
    make_debug_info(sfs, curr_C, is_forward)



def main():
    print('\n****************************************************************')
    print('* Process started with C =', sys.argv[1])
    print('****************************************************************\n')

    X_train = joblib.load('../../data/X_train.pkl')
    y_train = joblib.load('../../data/y_train.pkl')

    # make_features_selection(X_train, y_train, True)
    make_features_selection(X_train, y_train, False)

    print('\n****************************************************************')
    print('* Process finished with C =', sys.argv[1])
    print('****************************************************************\n')


if __name__ == "__main__":
    main()



