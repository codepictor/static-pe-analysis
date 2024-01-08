"""The module helps to collect features about given PE file."""

import math
import collections


COMMON_SECTION_NAMES = {
    # common section names
    b".00cfg", # – Control Flow Guard (CFG) section(added by newer versions of Visual Studio)
    b".arch", # – Alpha-architecture section
    b".bindat", # – Binary data (also used by one of the downware installers based on LUA)
    b".bootdat", # – section that can be found inside Visual Studio files; contains palette entries
    b".bss", # – Uninitialized Data Section
    b".BSS", # – Uninitialized Data
    b".buildid", # – gcc/cygwin; Contains debug information (if overlaps with debug directory)
    b".CLR_UEF", # – .CLR Unhandled Exception Handler section; see https://github.com/dotnet/coreclr/blob/master/src/vm/excep.h
    b".code", # – Code Section
    b".cormeta", # – .CLR Metadata Section
    b".complua", # – Binary data, most likely compiled LUA (also used by one of the downware installers based on LUA)
    b".CRT", # – Initialized Data Section  (C RunTime)
    b".data", # – Data Section
    b".DATA", # – Data Section
    b".data1", # – Data Section
    b".data2", # – Data Section
    b".data3", # – Data Section
    b".debug", # – Debug info Section
    b".debug$F", # – Debug info Section (Visual C++ version <7.0)
    b".debug$P", # – Debug info Section (Visual C++ debug information – precompiled information
    b".debug$S", # – Debug info Section (Visual C++ debug information – symbolic information)
    b".debug$T", # – Debug info Section (Visual C++ debug information – type information)
    b".drectve", #  – directive section (temporary, linker removes it after processing it; should not appear in a final PE image)
    b".didat", # – Delay Import Section
    b".didata", # – Delay Import Section
    b".edata", # – Export Data Section
    b".eh_fram", # – gcc/cygwin; Exception Handler Frame section
    b".export", # – Alternative Export Data Section
    b".fasm", # – FASM flat Section
    b".flat", # – FASM flat Section
    b".gfids", # – section added by new Visual Studio (14.0); purpose unknown
    b".giats", # – section added by new Visual Studio (14.0); purpose unknown
    b".gljmp", # – section added by new Visual Studio (14.0); purpose unknown
    b".glue_7t", # – ARMv7 core glue functions (thumb mode)
    b".glue_7", # – ARMv7 core glue functions (32-bit ARM mode)
    b".idata", # – Initialized Data Section  (Borland)
    b".idlsym", # – IDL Attributes (registered SEH)
    b".impdata", # – Alternative Import data section
    b".itext", # – Code Section  (Borland)
    b".ndata", # – Nullsoft Installer section
    b".orpc", # – Code section inside rpcrt4.dll
    b".pdata", # – Exception Handling Functions Section (PDATA records)
    b".rdata", # – Read-only initialized Data Section  (MS and Borland)
    b".reloc", # – Relocations Section
    b".rodata", # – Read-only Data Section
    b".rsrc", # – Resource section
    b".sbss", # – GP-relative Uninitialized Data Section
    b".script", # – Section containing script
    b".shared", # – Shared section
    b".sdata", # – GP-relative Initialized Data Section
    b".srdata", # – GP-relative Read-only Data Section
    b".stab", # – Created by Haskell compiler (GHC)
    b".stabstr", # – Created by Haskell compiler (GHC)
    b".sxdata", # – Registered Exception Handlers Section
    b".text", # – Code Section
    b".text0", # – Alternative Code Section
    b".text1", # – Alternative Code Section
    b".text2", # – Alternative Code Section
    b".text3", # – Alternative Code Section
    b".textbss", # – Section used by incremental linking
    b".tls", # – Thread Local Storage Section
    b".tls$", # – Thread Local Storage Section
    b".udata", # – Uninitialized Data Section
    b".vsdata", # – GP-relative Initialized Data
    b".xdata", # – Exception Information Section
    b".wixburn", # – Wix section

    # The packer/protector/tools section names/keywords
    b".aspack", # – Aspack packer
    b".adata", # – Aspack packer/Armadillo packer
    b".ASPack", # – ASPAck Protector
    b".boom", # – The Boomerang List Builder (config+exe xored with a single byte key 0x77)
    b".ccg", # – CCG Packer (Chinese Packer)
    b".charmve", # – Added by the PIN tool
    b".gentee", # – Gentee installer
    b".mackt", # – ImpRec-created section
    b".MaskPE", # – MaskPE Packer
    b".MPRESS1", # – Mpress Packer
    b".MPRESS2", # – Mpress Packer
    b".neolite", # – Neolite Packer
    b".neolit", # – Neolite Packer
    b".nsp1", # – NsPack packer
    b".nsp0", # – NsPack packer
    b".nsp2", # – NsPack packer
    b".packed", # – RLPack Packer (first section)
    b".perplex", # – Perplex PE-Protector
    b".petite", # – Petite Packer
    b".pinclie", # – Added by the PIN tool
    b".RLPack", # – RLPack Packer (second section)
    b".rmnet", # – Ramnit virus marker
    b".RPCrypt", # – RPCrypt Packer
    b".seau", # – SeauSFX Packer
    b".sforce3", # – StarForce Protection
    b".spack", # – Simple Pack (by bagie)
    b".svkp", # – SVKP packer
    b".Themida", # – Themida Packer
    b".taz", # – Some version os PESpin
    b".tsuarch", # – TSULoader
    b".tsustub", # – TSULoader
    b".packed", # – Unknown Packer
    b".Upack", # – Upack packer
    b".ByDwing", # – Upack Packer
    b".UPX0", # – UPX Packer
    b".UPX1", # – UPX Packer
    b".UPX2", # – UPX Packer
    b".vmp0", # – VMProtect packer
    b".vmp1", # – VMProtect packer
    b".vmp2", # – VMProtect packer
    b".winapi", # – Added by API Override tool
    b".WWPACK", # – WWPACK Packer
    b".yP", # – Y0da Protector
    b".y0da", # – Y0da Protector
}


def get_entropy(b_data):
    """
    Calculate the entropy of a chunk of data.
    data should be in bytes
    """
    if len(b_data) == 0:
        return 0.0

    occurences = collections.Counter(b_data)
    entropy = 0
    for x in occurences.values():
        p_x = float(x)/len(b_data)
        entropy -= p_x*math.log(p_x, 2)
    return entropy


class PEInfo(object):
    """A handler that collects info about a PE file."""
    def __init__(self, pef):
        self._pef = pef

    def common(self):
        features = {
            'is_exe': int(self._pef.is_exe()),
            'is_dll': int(self._pef.is_dll()),
            'is_driver': int(self._pef.is_driver()),
        }
        return features

    def DOSHeader(self):
        features = {
            'DOS_HEADER/collapsed': int(
                self._pef.DOS_HEADER.e_lfanew > len(self._pef.get_data())/2
                or self._pef.DOS_HEADER.e_lfanew < 0x40
            ),
            'DOS_HEADER.e_cblp': self._pef.DOS_HEADER.e_cblp,
            'DOS_HEADER.e_cp': self._pef.DOS_HEADER.e_cp,
            'DOS_HEADER.e_crlc': self._pef.DOS_HEADER.e_crlc,
            'DOS_HEADER.e_cparhdr': self._pef.DOS_HEADER.e_cparhdr,
            'DOS_HEADER.e_minalloc': self._pef.DOS_HEADER.e_minalloc,
            'DOS_HEADER.e_maxalloc': self._pef.DOS_HEADER.e_maxalloc,
            'DOS_HEADER.e_ss': self._pef.DOS_HEADER.e_ss,
            'DOS_HEADER.e_csum': self._pef.DOS_HEADER.e_csum,
            'DOS_HEADER.e_ip': self._pef.DOS_HEADER.e_ip,
            'DOS_HEADER.e_cs': self._pef.DOS_HEADER.e_cs,
            'DOS_HEADER.e_lfarlc': self._pef.DOS_HEADER.e_lfarlc,
            'DOS_HEADER.e_ovno': self._pef.DOS_HEADER.e_ovno,
            'DOS_HEADER.e_oemid': self._pef.DOS_HEADER.e_oemid,
            'DOS_HEADER.e_oeminfo': self._pef.DOS_HEADER.e_oeminfo,
            'DOS_HEADER.e_lfanew': self._pef.DOS_HEADER.e_lfanew,

            'DOS_HEADER.e_res/empty': int(
                self._pef.DOS_HEADER.e_res == b'\x00'*8
            ),
            'DOS_HEADER.e_res2/empty': int(
                self._pef.DOS_HEADER.e_res2 == b'\x00'*20
            ),
        }
        return features

    def DOSStub(self):
        features = {}
        stud_end = self._pef.DOS_HEADER.e_lfanew
        stub = self._pef.__data__[64:stud_end]

        features['DOSStub/entropy'] = get_entropy(stub)
        features['DOSStub/zeros'] = (collections.Counter(stub)[0]/len(stub)
                                     if len(stub) else 1.0)
        return features

    def NTHeaders(self):
        features = {
            'NTHeaders.Signature': self._pef.NT_HEADERS.Signature
        }
        return features

    def OptionalHeader(self):
        def is_power2(num):
            return num != 0 and ((num & (num - 1)) == 0)

        try:
            base_of_data = self._pef.OPTIONAL_HEADER.BaseOfData
        except AttributeError as err:
            base_of_data = 0

        features = {
            'OPTIONAL_HEADER.SizeOfImage':
                self._pef.OPTIONAL_HEADER.SizeOfImage,
            'OPTIONAL_HEADER.ImageBase':
                self._pef.OPTIONAL_HEADER.ImageBase,
            'OPTIONAL_HEADER.FileAlignment':
                self._pef.OPTIONAL_HEADER.FileAlignment,
            'OPTIONAL_HEADER.DATA_DIRECTORY/size':
                len(self._pef.OPTIONAL_HEADER.DATA_DIRECTORY),
            'OPTIONAL_HEADER.SizeOfHeaders':
                self._pef.OPTIONAL_HEADER.SizeOfHeaders,
            'OPTIONAL_HEADER.SectionAlignment':
                self._pef.OPTIONAL_HEADER.SectionAlignment,
            'OPTIONAL_HEADER.AddressOfEntryPoint':
                self._pef.OPTIONAL_HEADER.AddressOfEntryPoint,
            'OPTIONAL_HEADER.MajorLinkerVersion':
                self._pef.OPTIONAL_HEADER.MajorLinkerVersion,
            'OPTIONAL_HEADER.MinorLinkerVersion':
                self._pef.OPTIONAL_HEADER.MinorLinkerVersion,
            'OPTIONAL_HEADER.SizeOfCode':
                self._pef.OPTIONAL_HEADER.SizeOfCode,
            'OPTIONAL_HEADER.SizeOfInitializedData':
                self._pef.OPTIONAL_HEADER.SizeOfInitializedData,
            'OPTIONAL_HEADER.SizeOfUninitializedData':
                self._pef.OPTIONAL_HEADER.SizeOfUninitializedData,
            'OPTIONAL_HEADER.BaseOfCode':
                self._pef.OPTIONAL_HEADER.BaseOfCode,
            'OPTIONAL_HEADER.BaseOfData':
                base_of_data,
            'OPTIONAL_HEADER.MajorOperatingSystemVersion':
                self._pef.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'OPTIONAL_HEADER.MinorOperatingSystemVersion':
                self._pef.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'OPTIONAL_HEADER.MajorImageVersion':
                self._pef.OPTIONAL_HEADER.MajorImageVersion,
            'OPTIONAL_HEADER.MinorImageVersion':
                self._pef.OPTIONAL_HEADER.MinorImageVersion,
            'OPTIONAL_HEADER.MajorSubsystemVersion':
                self._pef.OPTIONAL_HEADER.MajorSubsystemVersion,
            'OPTIONAL_HEADER.MinorSubsystemVersion':
                self._pef.OPTIONAL_HEADER.MinorSubsystemVersion,
            'OPTIONAL_HEADER.Reserved1':
                self._pef.OPTIONAL_HEADER.Reserved1,
            'OPTIONAL_HEADER.Subsystem':
                self._pef.OPTIONAL_HEADER.Subsystem,
            'OPTIONAL_HEADER.SizeOfStackReserve':
                self._pef.OPTIONAL_HEADER.SizeOfStackReserve,
            'OPTIONAL_HEADER.SizeOfStackCommit':
                self._pef.OPTIONAL_HEADER.SizeOfStackCommit,
            'OPTIONAL_HEADER.SizeOfHeapReserve':
                self._pef.OPTIONAL_HEADER.SizeOfHeapReserve,
            'OPTIONAL_HEADER.SizeOfHeapCommit':
                self._pef.OPTIONAL_HEADER.SizeOfHeapCommit,
            'OPTIONAL_HEADER.LoaderFlags':
                self._pef.OPTIONAL_HEADER.LoaderFlags,
            'OPTIONAL_HEADER.NumberOfRvaAndSizes':
                self._pef.OPTIONAL_HEADER.NumberOfRvaAndSizes,
            'OPTIONAL_HEADER.ImageBase/standard': int(
                self._pef.OPTIONAL_HEADER.ImageBase == 0x00400000
            ),
            'OPTIONAL_HEADER.SizeOfImage/alignment': int(
                self._pef.OPTIONAL_HEADER.SizeOfImage
                % self._pef.OPTIONAL_HEADER.SectionAlignment != 0
            ),
            'OPTIONAL_HEADER/ImageBase+SizeOfImage/addr': int(
                self._pef.OPTIONAL_HEADER.ImageBase
                + self._pef.OPTIONAL_HEADER.SizeOfImage >= 0x80000000
            ),
            'OPTIONAL_HEADER.SizeOfHeaders/alignment': int(
                self._pef.OPTIONAL_HEADER.SizeOfHeaders
                % max(self._pef.OPTIONAL_HEADER.FileAlignment, 1) != 0
            ),
            'OPTIONAL_HEADER.ImageBase/alignment': int(
                self._pef.OPTIONAL_HEADER.ImageBase % (64*1024) == 0
            ),
            'OPTIONAL_HEADER.FileAlignment/isAlignment': int(
                is_power2(self._pef.OPTIONAL_HEADER.FileAlignment)
            ),
            'OPTIONAL_HEADER.SectionAlignment/>FileAlignment': int(
                self._pef.OPTIONAL_HEADER.SectionAlignment
                > self._pef.OPTIONAL_HEADER.FileAlignment
            ),
            'OPTIONAL_HEADER.AddressOfEntryPoint/>=SizeOfHeaders': int(
                self._pef.OPTIONAL_HEADER.AddressOfEntryPoint
                >= self._pef.OPTIONAL_HEADER.SizeOfHeaders
            ),
        }

        # dll_characteristics = [x for x in self._pef.OPTIONAL_HEADER.__dict__
        #                        if x.startswith('IMAGE_DLLCHARACTERISTICS_')]
        # for characteristic in dll_characteristics:
        #     features['FILE_HEADER.DllCharacteristics/' + characteristic] = int(
        #         getattr(self._pef.OPTIONAL_HEADER, characteristic)
        #     )
        return features

    def DataDirectories(self):
        features = {}
        directory_name_count = 0
        for directory_name in [
                'DIRECTORY_ENTRY_EXPORT',
                'DIRECTORY_ENTRY_IMPORT',
                'DIRECTORY_ENTRY_RESOURCE',
                'DIRECTORY_ENTRY_BOUND_IMPORT',
                'DIRECTORY_ENTRY_DELAY_IMPORT',
                'DIRECTORY_ENTRY_TLS',
                'DIRECTORY_ENTRY_DEBUG']:
            if hasattr(self._pef, directory_name):
                if isinstance(getattr(self._pef, directory_name), list):
                    features[directory_name + '/exists'] = len(
                        getattr(self._pef, directory_name)
                    )
                else:
                    features[directory_name + '/exists'] = 1
            else:
                features[directory_name + '/exists'] = 0
            directory_name_count += 1
        features['DIRECTORY_ENTRY/count'] = directory_name_count
        return features

    def FileHeader(self):
        features = {
            'FILE_HEADER.SizeOfOptionalHeader':
                self._pef.FILE_HEADER.SizeOfOptionalHeader,
            'FILE_HEADER.NumberOfSections':
                self._pef.FILE_HEADER.NumberOfSections,
            'FILE_HEADER.NumberOfSymbols':
                self._pef.FILE_HEADER.NumberOfSymbols,
            'FILE_HEADER.PointerToSymbolTable':
                self._pef.FILE_HEADER.PointerToSymbolTable,
            'FILE_HEADER.Machine':
                self._pef.FILE_HEADER.Machine,
        }

        characteristics = [x for x in self._pef.FILE_HEADER.__dict__
                           if x.startswith('IMAGE_FILE_')]
        for characteristic in characteristics:
            features['FILE_HEADER.Characteristics/' + characteristic] = int(
                getattr(self._pef.FILE_HEADER, characteristic)
            )
        return features

    def SectionHeaders(self):
        IMAGE_SCN_MEM_EXECUTE = 0x20000000  # the section can be executed
        IMAGE_SCN_MEM_WRITE = 0x80000000  # the section can be written to
        sections_number = len(self._pef.sections)
        last_section = None
        if sections_number >= 1:
            last_section = self._pef.sections[sections_number - 1]
        entry_section = self._pef.get_section_by_rva(
            self._pef.OPTIONAL_HEADER.AddressOfEntryPoint
        )

        features = {
            'SECTIONS.PointerToLinenumbers/set': 0,
            'SECTIONS.NumberOfLinenumbers/set': 0,
            'SECTIONS.PointerToRelocations/set': 0,
            'SECTIONS/entry_point_in_last_section': int(
                entry_section is last_section
            ),
            'SECTIONS/writeable_and_executable_sections': 0,
            'SECTIONS/writeable_sections': 0,
            'SECTIONS/executable_sections': 0,
            'SECTIONS.SizeOfRawData/alignment': 0,
            'SECTIONS.SizeOfRawData/zero': 0,
            'SECTIONS/text_section_entropy': 0,
            'SECTIONS/rsrc_section_entropy': 0,
            'SECTIONS/average_section_entropy': 0,
            'SECTIONS/max_section_entropy': 0,
            'SECTIONS/unusual_section_names': 0,
            'SECTIONS/entry_point_in_writeable_section': int(
                (entry_section.Characteristics & IMAGE_SCN_MEM_WRITE)
                if entry_section else 0
            )
        }

        average_section_entropy = 0.0
        max_section_entropy = 0.0
        sections_with_zero_entropy_count = 0
        for section in self._pef.sections:
            # deprecated fields
            if section.PointerToLinenumbers != 0:
                features['SECTIONS.PointerToLinenumbers/set'] += 1
            if section.NumberOfLinenumbers != 0:
                features['SECTIONS.NumberOfLinenumbers/set'] += 1
            if section.PointerToRelocations != 0:
                features['SECTIONS.PointerToRelocations/set'] += 1

            # Anomalies connected with SizeOfRawData
            if (self._pef.OPTIONAL_HEADER.FileAlignment != 0
                    and section.SizeOfRawData
                    % self._pef.OPTIONAL_HEADER.FileAlignment != 0):
                features['SECTIONS.SizeOfRawData/alignment'] += 1
            if section.SizeOfRawData == 0:
                features['SECTIONS.SizeOfRawData/zero'] += 1

            # 0.0 <= section_entropy <= 8.0
            section_entropy = section.get_entropy()
            average_section_entropy += section_entropy
            if section_entropy > max_section_entropy:
                max_section_entropy = section_entropy
            if section_entropy == 0:
                sections_with_zero_entropy_count += 1

            if (section.Characteristics & IMAGE_SCN_MEM_WRITE
                    and section.Characteristics & IMAGE_SCN_MEM_EXECUTE):
                features['SECTIONS/writeable_and_executable_sections'] += 1
            if section.Characteristics & IMAGE_SCN_MEM_WRITE:
                features['SECTIONS/writeable_sections'] += 1
            if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
                features['SECTIONS/executable_sections'] += 1

            # checking whether name of the section is unusual or not
            section_name = section.Name.rstrip(b"\x00")
            if section_name not in COMMON_SECTION_NAMES:
                features['SECTIONS/unusual_section_names'] += 1

            if section.Name == b'.text\x00\x00\x00':
                features['SECTIONS/text_section_entropy'] = (
                    section.get_entropy()
                )
            if section.Name == b'.rsrc\x00\x00\x00':
                features['SECTIONS/rsrc_section_entropy'] = (
                    section.get_entropy()
                )

        features['SECTIONS/sections_with_zero_entropy_count'] = (
            sections_with_zero_entropy_count
        )
        features['SECTIONS/max_section_entropy'] = (
            max_section_entropy
        )
        features['SECTIONS/average_section_entropy'] = (
            0.0 if not self._pef.sections
                else average_section_entropy/len(self._pef.sections)
        )
        return features

    def get_features(self):
        """Calls all methods in class (except for get_features)."""
        features = {}
        methods = [func for func in dir(self) if callable(getattr(self, func))]
        methods = filter(
            lambda method:
            not method.startswith('_') and method != 'get_features',
            methods
        )
        for method_name in methods:
            method = getattr(self, method_name)
            features.update(method())
        return features


def get_features(pef):
    return PEInfo(pef).get_features()
