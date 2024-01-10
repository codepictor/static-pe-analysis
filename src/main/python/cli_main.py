import os
import os.path
import optparse

from pe import static_pe_analyzer


def print_intro(args):
    """"""
    assert len(args) >= 0

    if len(args) != 1:
        print('Incorrect number of arguments:', len(args))
        print('Only one argument (path to a PE file or a dir)', end=' ')
        print('should be provided.')
        return False

    selected_path = args[0]
    if os.path.isfile(selected_path):
        print('Analyzing the following file: "{0}" ...'.format(selected_path))
    elif os.path.isdir(selected_path):
        print('Recursive analyzing files in "{0}" ...'.format(selected_path))
        print('All files except for exe-files will be skipped.\n')
        print('*********************************************************\n')
    else:
        print('"{0}":'.format(selected_path), end=' ')
        print('should be path to a PE file or directory containing PE files.')
        return False

    return True


def print_summary(unusual_files, unpredicted_files, scanned_files_n):
    """"""
    assert len(unusual_files) >= 0
    assert len(unpredicted_files) >= 0
    assert scanned_files_n >= 0

    print('\nUNUSUAL FILES:', len(unusual_files))
    for prediction in unusual_files:
        print('"{0}"  SCORE = {1}'.format(
            prediction['path_to_file'], prediction['score']
        ))

    print('\nFILES WITHOUT ANY PREDICTION:', len(unpredicted_files))
    # for prediction in unpredicted_files:
    #     print('"{0}"  NOTE: {1}'.format(
    #         prediction['path_to_file'], prediction['note']
    #     ))

    print('\nTOTAL FILES SCANNED:', scanned_files_n)


def main():
    parser = optparse.OptionParser()
    opts, args = parser.parse_args()
    if not print_intro(args):
        return

    selected_path = args[0]
    classifier = static_pe_analyzer.get_classifier()
    unusual_files = []
    unpredicted_files = []
    scanned_files_n = 0

    paths_to_pe_files = static_pe_analyzer.get_paths_to_pe_files(selected_path)
    for path_to_pe_file in paths_to_pe_files:
        print(path_to_pe_file, ': ', end=' ')
        scanned_files_n += 1
        try:
            prediction = static_pe_analyzer.get_prediction(
                path_to_pe_file, classifier
            )
            if prediction['label'] is None:
                print('[NO PREDICTION]  NOTE:', prediction['note'])
                unpredicted_files.append(prediction)
            elif prediction['label']:
                print('[UNUSUAL]  SCORE =', prediction['score'])
                unusual_files.append(prediction)
            else:
                print('[CLEAR]  SCORE =', prediction['score'])
        except Exception as e:
            print('[NO PREDICTION]  ERROR:', str(e))
            unpredicted_files.append({
                'path_to_file': path_to_pe_file,
                'label': None,
                # 'proba': None,
                'score': None,
                'note': str(e)
            })

    print('\n*********************************************************\n')
    print_summary(unusual_files, unpredicted_files, scanned_files_n)


if __name__ == '__main__':
    main()
