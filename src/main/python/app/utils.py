import os
import os.path

from pe import pe_utils


def get_paths_to_pe_files(path):
    """"""
    assert os.path.isfile(path) or os.path.isdir(path)

    if os.path.isfile(path):
        if pe_utils.is_pe_file(path):
            yield path

    else:
        for root, dirs, files in os.walk(path):
            for filename in files:
                path_to_file = os.path.join(root, filename)
                if pe_utils.is_pe_file(path_to_file):
                    yield path_to_file
