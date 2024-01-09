# import os
import hashlib
# import subprocess

# import pefile


DOS_HEADER_SIZE = 64
PE_MAGIC = b"\x4d\x5a"
PE_SIGNATURE = b"\x50\x45\x00\x00"
PE_HEADER_PTR_SIZE = 4


def read_file_in_chunks(fh, chunk_size=8192):
    """Lazy function (generator) to read a file chunk by chunk."""
    while True:
        data = fh.read(chunk_size)
        if not data:
            fh.seek(0, 0)
            break
        yield data


def get_signature(filepath):
    """Calculates SHA-256 hash of the given file."""
    with open(filepath, "rb") as fh:
        hash_sha256 = hashlib.sha256()
        for chunk in read_file_in_chunks(fh):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def is_pe_file(filepath):
    """Checks if the given file is a PE file."""
    try:
        with open(filepath, "rb") as fh:
            dos_header = fh.read(DOS_HEADER_SIZE)
            if len(dos_header) < DOS_HEADER_SIZE:
                return False

            pe_header_offset = int.from_bytes(
                dos_header[-PE_HEADER_PTR_SIZE:],
                byteorder="little"
            )
            fh.seek(pe_header_offset, 0)
            signature = fh.read(len(PE_SIGNATURE))
            if (dos_header[:len(PE_MAGIC)] == PE_MAGIC
                    and signature == PE_SIGNATURE):
                return True

    except OSError as e:
        # print("ERROR. FILE:", filepath, ";", e)
        pass
    return False


# def verify_pe_file(path_to_pe_file):
#     process = subprocess.Popen(
#         ["VerifyPE.exe", path_to_pe_file],
#         stdout=subprocess.PIPE
#     )
#     # (output, err) = process.communicate()
#
#     exit_code = process.wait()
#     return exit_code


# def check_signature_existence(pe_file_path):
#     pe = pefile.PE(pe_file_path, fast_load=True)
#     sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
#         pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
#     ]
#     address = sec_dir.VirtualAddress
#     # size = sec_dir.Size
#     pe.close()
#
#     if address == 0:
#         return False
#     else:
#         return True


# def iget_path_to_pe_file(folder):
#     for root, dirs, files in os.walk(folder):
#         for filename in files:
#             filepath = os.path.join(root, filename)
#             if is_pe_file(filepath):
#                 yield filepath


# def iget_pe(paths_with_flags):
#     for folder, is_malware, limit in paths_with_flags:
#         print('folder: {}'.format(folder))
#         for path_to_pe_file in iget_path_to_pe_file(folder):
#             try:
#                 pe = pefile.PE(path_to_pe_file)
#                 if not pe.is_exe():
#                     continue
#                 if limit <= 0:
#                     break
#                 limit -= 1
#                 yield pe, is_malware, path_to_pe_file
#             except Exception as err:
#                 print('WARNING! Problems with parsing', path_to_pe_file, ':', err)
#                 continue
