import os
import os.path

import pefile
import numpy as np
import pandas as pd
from sklearn.externals import joblib

from . import collect_features
from . import pe_utils


# Don't change these values!
REQUIRED_FEATURES = (
    'DIRECTORY_ENTRY_BOUND_IMPORT/exists',
    'DIRECTORY_ENTRY_DEBUG/exists',
    'DIRECTORY_ENTRY_DELAY_IMPORT/exists',
    'DIRECTORY_ENTRY_EXPORT/exists',
    'DIRECTORY_ENTRY_IMPORT/exists',
    'DIRECTORY_ENTRY_RESOURCE/exists',
    'DIRECTORY_ENTRY_TLS/exists',
    'DOSStub/entropy',
    'DOSStub/zeros',
    'DOS_HEADER.e_cblp',
    'DOS_HEADER.e_cp',
    'DOS_HEADER.e_cparhdr',
    'DOS_HEADER.e_crlc',
    'DOS_HEADER.e_cs',
    'DOS_HEADER.e_csum',
    'DOS_HEADER.e_ip',
    'DOS_HEADER.e_lfanew',
    'DOS_HEADER.e_lfarlc',
    'DOS_HEADER.e_maxalloc',
    'DOS_HEADER.e_minalloc',
    'DOS_HEADER.e_oemid',
    'DOS_HEADER.e_oeminfo',
    'DOS_HEADER.e_ovno',
    'DOS_HEADER.e_res/empty',
    'DOS_HEADER.e_res2/empty',
    'DOS_HEADER.e_ss',
    'DOS_HEADER/collapsed',
    'FILE_HEADER.Characteristics/IMAGE_FILE_16BIT_MACHINE',
    'FILE_HEADER.Characteristics/IMAGE_FILE_32BIT_MACHINE',
    'FILE_HEADER.Characteristics/IMAGE_FILE_AGGRESIVE_WS_TRIM',
    'FILE_HEADER.Characteristics/IMAGE_FILE_BYTES_REVERSED_HI',
    'FILE_HEADER.Characteristics/IMAGE_FILE_BYTES_REVERSED_LO',
    'FILE_HEADER.Characteristics/IMAGE_FILE_DEBUG_STRIPPED',
    'FILE_HEADER.Characteristics/IMAGE_FILE_LARGE_ADDRESS_AWARE',
    'FILE_HEADER.Characteristics/IMAGE_FILE_LINE_NUMS_STRIPPED',
    'FILE_HEADER.Characteristics/IMAGE_FILE_LOCAL_SYMS_STRIPPED',
    'FILE_HEADER.Characteristics/IMAGE_FILE_NET_RUN_FROM_SWAP',
    'FILE_HEADER.Characteristics/IMAGE_FILE_RELOCS_STRIPPED',
    'FILE_HEADER.Characteristics/IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP',
    'FILE_HEADER.Characteristics/IMAGE_FILE_SYSTEM',
    'FILE_HEADER.Characteristics/IMAGE_FILE_UP_SYSTEM_ONLY',
    'FILE_HEADER.Machine',
    'FILE_HEADER.NumberOfSections',
    'FILE_HEADER.NumberOfSymbols',
    'FILE_HEADER.PointerToSymbolTable',
    'FILE_HEADER.SizeOfOptionalHeader',
    'OPTIONAL_HEADER.AddressOfEntryPoint',
    'OPTIONAL_HEADER.AddressOfEntryPoint/>=SizeOfHeaders',
    'OPTIONAL_HEADER.BaseOfCode',
    'OPTIONAL_HEADER.BaseOfData',
    'OPTIONAL_HEADER.DATA_DIRECTORY/size',
    'OPTIONAL_HEADER.FileAlignment',
    'OPTIONAL_HEADER.ImageBase',
    'OPTIONAL_HEADER.ImageBase/standard',
    'OPTIONAL_HEADER.LoaderFlags',
    'OPTIONAL_HEADER.MajorImageVersion',
    'OPTIONAL_HEADER.MajorLinkerVersion',
    'OPTIONAL_HEADER.MajorOperatingSystemVersion',
    'OPTIONAL_HEADER.MajorSubsystemVersion',
    'OPTIONAL_HEADER.MinorImageVersion',
    'OPTIONAL_HEADER.MinorLinkerVersion',
    'OPTIONAL_HEADER.MinorOperatingSystemVersion',
    'OPTIONAL_HEADER.MinorSubsystemVersion',
    'OPTIONAL_HEADER.NumberOfRvaAndSizes',
    'OPTIONAL_HEADER.Reserved1',
    'OPTIONAL_HEADER.SectionAlignment',
    'OPTIONAL_HEADER.SectionAlignment/>FileAlignment',
    'OPTIONAL_HEADER.SizeOfCode',
    'OPTIONAL_HEADER.SizeOfHeaders',
    'OPTIONAL_HEADER.SizeOfHeaders/alignment',
    'OPTIONAL_HEADER.SizeOfHeapCommit',
    'OPTIONAL_HEADER.SizeOfHeapReserve',
    'OPTIONAL_HEADER.SizeOfImage',
    'OPTIONAL_HEADER.SizeOfImage/alignment',
    'OPTIONAL_HEADER.SizeOfInitializedData',
    'OPTIONAL_HEADER.SizeOfStackCommit',
    'OPTIONAL_HEADER.SizeOfStackReserve',
    'OPTIONAL_HEADER.SizeOfUninitializedData',
    'OPTIONAL_HEADER.Subsystem',
    'OPTIONAL_HEADER/ImageBase+SizeOfImage/addr',
    'SECTIONS.NumberOfLinenumbers/set',
    'SECTIONS.PointerToLinenumbers/set',
    'SECTIONS.PointerToRelocations/set',
    'SECTIONS.SizeOfRawData/alignment',
    'SECTIONS.SizeOfRawData/zero',
    'SECTIONS/average_section_entropy',
    'SECTIONS/entry_point_in_last_section',
    'SECTIONS/entry_point_in_writeable_section',
    'SECTIONS/executable_sections',
    'SECTIONS/max_section_entropy',
    'SECTIONS/rsrc_section_entropy',
    'SECTIONS/sections_with_zero_entropy_count',
    'SECTIONS/text_section_entropy',
    'SECTIONS/unusual_section_names',
    'SECTIONS/writeable_and_executable_sections',
    'SECTIONS/writeable_sections',
)


# Don't change these values!
MEANS = (
    1.89851558e-01,   3.78747795e-01,   2.16967960e-01,
    8.48214286e-02,   7.79030717e+00,   8.99654615e-01,
    2.04622281e-01,   4.39527479e+00,   2.57128751e-01,
    1.52020154e+02,   4.59290858e+01,   2.56214727e+01,
    1.76208848e+01,   1.56726925e+01,   1.36676955e+01,
    5.35784098e+01,   2.99907628e+02,   1.84386188e+02,
    6.52748755e+04,   2.19449405e+01,   3.51895870e+02,
    3.02961163e+02,   1.25031452e+02,   9.82179600e-01,
    9.65369636e-01,   1.21803902e+01,   1.32642563e-02,
    4.22545561e-04,   9.50451940e-01,   2.22295708e-03,
    1.59465021e-01,   1.59850823e-01,   6.05709877e-02,
    8.02101705e-02,   6.14656820e-01,   5.94246032e-01,
    9.99412111e-03,   6.37694738e-01,   1.77652851e-02,
    4.22545561e-04,   9.18577307e-05,   1.74238760e+03,
    5.17122281e+00,   2.73761356e+06,   4.04312935e+06,
    2.24715021e+02,   1.24941964e+06,   9.97666814e-01,
    1.23158542e+05,   6.37085213e+05,   1.59959031e+01,
    1.17232922e+03,   6.77790290e+14,   9.09905938e-01,
    1.35427391e+06,   1.91168798e+01,   7.02838404e+00,
    5.44881687e+00,   4.46487360e+00,   1.50761501e+01,
    1.02312794e+01,   1.95634921e+00,   7.95911780e+01,
    3.10423284e+05,   3.29440403e+00,   1.27678613e+04,
    8.16688713e-01,   1.51221780e+06,   1.98044268e+03,
    6.43004115e-04,   3.48555302e+05,   1.07473131e+06,
    1.93072386e+06,   9.29600235e-03,   2.34000501e+06,
    5.10514827e+04,   1.19461561e+06,   4.04680599e+05,
    2.06332672e+00,   3.36750441e-02,   1.59465021e-02,
    1.41093474e-02,   1.05085244e-02,   1.76917989e-01,
    5.93400941e-01,   4.21230029e+00,   4.92173721e-02,
    3.64541977e+08,   1.32107951e+00,   6.76815274e+00,
    4.39206787e+00,   7.19742063e-01,   5.02729660e+00,
    7.78310553e-01,   3.57657260e-01,   2.16786082e+00
)


# Don't change these values!
VARIATIONS = (
    1.69587878e+00,   2.29397365e+01,   2.08861714e+00,
    7.76267538e-02,   1.02430419e+02,   9.02761888e-02,
    1.62752003e-01,   1.43364871e+00,   5.92756881e-02,
    4.96028497e+05,   1.18972144e+06,   5.05583816e+05,
    3.97902764e+05,   4.74253025e+05,   5.11732667e+05,
    2.13499754e+06,   1.22002258e+07,   4.85250920e+06,
    1.32160056e+07,   4.75491679e+05,   1.42138553e+07,
    1.26565043e+07,   3.41549806e+06,   1.75028331e-02,
    3.34311023e-02,   3.43304772e+05,   1.30883158e-02,
    4.22367017e-04,   4.70930497e-02,   2.21801555e-03,
    1.34035928e-01,   1.34298537e-01,   5.69021431e-02,
    7.37764990e-02,   2.36853814e-01,   2.41117686e-01,
    9.89423865e-03,   2.31040159e-01,   1.74496798e-02,
    4.22367017e-04,   9.18492929e-05,   4.61418918e+07,
    5.21013748e+00,   4.81666315e+15,   1.19530069e+16,
    1.55957415e+01,   1.14731682e+15,   2.32774260e-03,
    2.80552027e+12,   8.97415268e+12,   1.99163434e-02,
    2.08317371e+06,   1.25025551e+34,   8.19771223e-02,
    5.20492560e+15,   3.88061908e+05,   5.19453841e+01,
    7.88930525e+04,   7.31754085e-01,   2.58093188e+05,
    3.20609961e+02,   7.41340799e+04,   5.16113577e+06,
    6.95612249e+14,   1.85196401e+05,   6.46524792e+11,
    1.49708259e-01,   1.61459636e+15,   9.71789890e+07,
    6.42590661e-04,   1.18145544e+15,   4.58906301e+12,
    6.24110410e+14,   9.20958669e-03,   4.38206373e+15,
    3.21205235e+11,   6.66920917e+12,   8.49100231e+14,
    1.63042196e-01,   3.25410355e-02,   2.58333046e-02,
    3.02976929e-02,   2.63813405e-02,   6.97866692e-01,
    9.39578733e-01,   1.25417432e+00,   4.67950224e-02,
    6.49957082e+17,   1.42341809e+00,   6.77692105e-01,
    4.70495470e+00,   1.17136363e+00,   6.84407231e+00,
    2.85162907e+00,   1.53624942e+00,   3.17627968e+00
)


def get_paths_to_pe_files(path):
    """A generator of paths to PE files.

    This function is auxiliary. It detects whether given path is a path
    to a single PE file or a directory with a lot of PE files
    (or maybe with subdirectories containing PE files).

    Args:
        path (str): path to a single PE file
                    or a directory containing PE files
    Returns:
        list: paths to PE files
    """
    if os.path.isfile(path) and pe_utils.is_pe_file(path):
        yield path
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for filename in files:
                path_to_file = os.path.join(root, filename)
                if pe_utils.is_pe_file(path_to_file):
                    yield path_to_file
    else:
        pass


def get_prepared_data(path_to_pe_file):
    """Returns features of the given PE file.

    Returns a dataframe which the classifier needs
    as the first return value and some additional features
    as the second return value.

    Args:
        path_to_pe_file (str): path to a PE file
    Returns:
        pandas.DataFrame: prepared data for the classifier
        dict: all raw features
    """
    pe = pefile.PE(path_to_pe_file)

    all_raw_features = collect_features.get_features(pe)
    filtered_features = dict()
    for feature_name in all_raw_features.keys():
        if feature_name in REQUIRED_FEATURES:
            filtered_features[feature_name] = float(
                all_raw_features[feature_name]
            )

    df = pd.DataFrame([filtered_features,])
    for i in range(len(df.columns)):
        df.iat[0, i] = (df.iat[0, i] - MEANS[i]) / (np.sqrt(VARIATIONS[i]))
    return df, all_raw_features


def get_prediction(path_to_pe_file, classifier):
    """Returns a prediction of the ML model for given PE file.

    Returns a tuple containing one label of the class
    (False -- clear, True -- unusual) and a score of given PE file.
    Returns (None, None) if it is impossible to make any prediction.

    Args:
        path_to_pe_file (str): path to a PE file
        classifier: classifier for making predictions
    Returns:
        prediction (dict): path to a PE-file (str)
                           label of the class (bool),
                           decision function value (float),
                           note (str)
    """
    input_df, all_raw_features = get_prepared_data(path_to_pe_file)
    assert len(input_df.shape) == 2 and input_df.shape[0] == 1

    if all_raw_features['is_exe'] < 0.5:
        return {
            'path_to_file': path_to_pe_file,
            'label': None,
            # 'proba': None,
            'score': None,
            'note': 'Now only .exe files are supported.'
        }

    score = classifier.decision_function(input_df)[0]
    # proba = classifier.predict_proba(input_df)[0, 1]
    return {
        'path_to_file': path_to_pe_file,
        'label': True if score >= 0.0 else False,
        # 'proba': proba,
        'score': float(score),
        'note': 'The model has been successfully applied.'
    }


def get_classifier():
    """Returns a fitted classifier for predictions.

    Constructs an absolute path to the classifier,
    loads it from the disk and returns it.
    """
    path_to_this_file = os.path.abspath(os.path.dirname(__file__))
    # path_to_classifier = os.path.join(
    #     path_to_this_file,
    #     '..',
    #     'results',
    #     'boosting',
    #     'boosting_classifier.pkl'
    # )
    path_to_classifier = os.path.join(
        path_to_this_file,
        '..', '..',
        'resources',
        'base',
        'model',
        'boosting_classifier.pkl'
    )
    classifier = joblib.load(path_to_classifier)
    return classifier
