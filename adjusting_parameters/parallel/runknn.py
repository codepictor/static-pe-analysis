import sys
import subprocess as sp

MAX_NUMBER_OF_NEIGHBORS = 15
WEIGHTS = ('distance', 'uniform')


def main():
    for i in range(1, MAX_NUMBER_OF_NEIGHBORS + 1, 2):
        for weights in WEIGHTS:
            try:
                proc = sp.Popen(
                    sys.executable + ' ./knn.py ' + str(i) + ' ' + weights,
                    shell=True
                )
                proc.wait()
            except Exception:
                proc.kill()
                sys.exit()

    print()
    print('********************************************')
    print('********** Successfully finished ***********')
    print('********************************************')


if __name__ == '__main__':
    main()


