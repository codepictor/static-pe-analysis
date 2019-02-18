import sys
import subprocess as sp

C = (0.25, 0.50, 0.75, 1.00, 1.25, 1.50, 1.75, 2.00)


def main():
    for curr_C in C:
        try:
            proc1 = sp.Popen(
                sys.executable + ' ./svm.py ' + str(curr_C),
                shell=True
            )
            proc1.wait()
        except Exception:
            proc1.kill()
            sys.exit()

    print()
    print('********************************************')
    print('********** Successfully finished ***********')
    print('********************************************')


if __name__ == '__main__':
    main()


