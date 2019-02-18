import sys
import subprocess as sp


def main():
    max_depths = (2, 3, 5, 8, 10, 15, 20, 25)
    procs = []
    for max_depth in max_depths:
        try:
            proc = sp.Popen(
                sys.executable + ' boosting.py ' + str(max_depth),
                shell=True
            )
            procs.append(proc)
        except Exception:
            proc.kill()
            sys.exit()

    for proc in procs:
        proc.wait()

    print()
    print('********************************************')
    print('********** Successfully finished ***********')
    print('********************************************')


if __name__ == '__main__':
    main()


