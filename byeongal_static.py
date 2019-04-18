import sys
import os
import math
import pefile
import peutils
import hashlib
import magic
import string
import ssdeep
import tlsh
import M2Crypto
import capstone

#import yara

import simplejson as json

from collections import Counter

_ROOT = os.path.abspath(os.path.dirname(__file__))
_USER_DB = os.path.join(_ROOT, 'signatures', 'userdb.txt')
#_ANTIDEBUG = os.path.join(_ROOT, 'signatures', 'AntiDebugging.yara')

def print_help () :
    pass

def entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = Counter(bytearray(data))
    entropy = 0
    for x in occurences.values():
        p_x = float(x) / len(data)
        entropy -= p_x*math.log(p_x, 2)

    return entropy

def isfile(file_path):
    if os.path.isfile(file_path):
        return True
    else :
        print("No file found.")
        exit()

def get_imphash( pe ):
    try :
        return pe.get_imphash()
    except :
        return ""

def get_hash(file_path):
    fh = open(file_path, 'rb')
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    s256 = hashlib.sha256()

    while True:
        data = fh.read(8192)
        if not data:
            break
        md5.update(data)
        sha1.update(data)
        s256.update(data)

    md5 = md5.hexdigest()
    sha1 = sha1.hexdigest()
    sha256 = s256.hexdigest()
    return md5, sha1, sha256

def get_compile_time(pe) :
    return pe.FILE_HEADER.TimeDateStamp

def get_packer_info( pe ) :
    signatures = peutils.SignatureDatabase(_USER_DB)
    matches = signatures.match_all(pe, ep_only=True)
    array = []
    if matches:
        for item in matches:
            if item[0] not in array:
                array.append(item[0])
    return array

def get_sections_number( pe ):
    return pe.FILE_HEADER.NumberOfSections

def get_resources_info( pe ) :
    res_array = []
    try :
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                name = "%s" % resource_type.name
            else:
                name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
            if name == None:
                name = "%d" % resource_type.struct.Id
            if hasattr(resource_type, 'directory') :
                for resource_id in resource_type.directory.entries :
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            raw_data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            ent = entropy(raw_data)
                            raw_data = [ format(i, '02x') for i in raw_data ]
                            # lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
                            # sublang = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)
                            res_array.append({"name": name, "data": raw_data, "offset": hex(resource_lang.data.struct.OffsetToData),"size": resource_lang.data.struct.Size, "entropy" : ent, "language": resource_lang.data.lang, "sublanguage": resource_lang.data.sublang})
    except :
        pass
    return res_array

def get_sections_info( pe ) :
    array = []
    for section in pe.sections:
        if section.SizeOfRawData == 0 or ( 0 < section.get_entropy() < 1) or section.get_entropy() > 7 :
            suspicious = True
        else:
            suspicious = False
        scn = section.Name
        md5 = section.get_hash_md5()
        sha1 = section.get_hash_sha1()
        spc = suspicious
        va = section.VirtualAddress
        vs = section.Misc_VirtualSize
        srd = section.SizeOfRawData
        entropy = section.get_entropy()
        array.append({"name": scn.decode().strip(' \t\r\n\0'), "hash_md5": md5, "hash_sha1": sha1, "suspicious": spc, "virtual_address": va, "virtual_size": vs, "size_raw_data": srd, "entropy" : entropy})

    return array

def get_import_function( pe ) :
    array = []
    library = set()
    libdict = {}
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll
            if dll == None :
                continue
            dll = dll.decode().strip(' \t\r\n\0')
            for imp in entry.imports:
                address = hex(imp.address)
                function = imp.name
                ordinal = imp.ordinal
                function = function.decode().strip(' \t\r\n\0')
                if dll not in library:
                    library.add(dll)
                array.append({"library": dll, "address": address, "function": function, "ordinal" : ordinal})

        for key in library:
            libdict[key] = []

        for lib in library:
            for item in array:
                if lib == item['library']:
                    libdict[lib].append({"address": item['address'], "function": item['function'], "ordinal" : item['ordinal']})
    except:
        pass

    return libdict

def get_export_function( pe ) :
    array = []
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name == None :
                continue
            # No dll
            address = hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
            function = exp.name.decode().strip(' \t\r\n\0')
            array.append({"address": address, "function": function})
    except:
        pass
    return array

# def get_anti_debug_info( file_data ) :
#     rules = yara.compile(_ANTIDEBUG)
#
#     matches = rules.match(data = file_data)
#
#     ret = []
#     for each in matches :
#         ret.append(each.rule)
#
#     return ret

def get_string( file_data ) :
    printable = set(string.printable)
    ret = set()
    found_str = ""
    for char in file_data :
        try :
            char = chr(char)
            if char in printable :
                found_str += char
            elif len(found_str) >= 4 :
                ret.add(found_str)
                found_str = ""
            else :
                found_str = ""
        except :
            found_str = ""
    return list(ret)

def get_fuzzy_hash( context ) :
    ret = dict()
    ret['ssdeep'] = ssdeep.hash(context)
    ret['tlsh'] = tlsh.hash(context)
    return ret

def get_feature_from_file_header( pe ) :
    FILE_HEADER = ['Machine', 'NumberOfSections', 'TimeDateStamp', 'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader', 'Characteristics']
    ret = dict()
    if hasattr(pe, 'FILE_HEADER') :
        for each in FILE_HEADER :
            ret[each] = getattr(pe.FILE_HEADER, each, None)
    return ret

def get_feature_from_optional_header( pe ) :
    OPTIONAL_HEADER = [ 'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode',
                       'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode',
                       'BaseOfData', 'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion',
                       'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion',
                       'MinorSubsystemVersion', 'Reserved1', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem',
                       'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve',
                       'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes']
    ret = dict()
    if hasattr(pe, 'OPTIONAL_HEADER') :
        for each in OPTIONAL_HEADER :
            ret[each] = getattr(pe.OPTIONAL_HEADER, each, None)
    return ret

def get_feature_from_data_directory( pe ) :
    DATA_DIRECTORY = ['IMAGE_DIRECTORY_ENTRY_EXPORT', 'IMAGE_DIRECTORY_ENTRY_IMPORT',
                                      'IMAGE_DIRECTORY_ENTRY_RESOURCE', 'IMAGE_DIRECTORY_ENTRY_EXCEPTION',
                                      'IMAGE_DIRECTORY_ENTRY_SECURITY', 'IMAGE_DIRECTORY_ENTRY_BASERELOC',
                                      'IMAGE_DIRECTORY_ENTRY_DEBUG', 'IMAGE_DIRECTORY_ENTRY_COPYRIGHT',
                                      'IMAGE_DIRECTORY_ENTRY_GLOBALPTR', 'IMAGE_DIRECTORY_ENTRY_TLS',
                                      'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG', 'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',
                                      'IMAGE_DIRECTORY_ENTRY_IAT', 'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',
                                      'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR', 'IMAGE_DIRECTORY_ENTRY_RESERVED']
    ret = list()
    if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') :
        for each in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            ret.append([each.name, each.VirtualAddress, each.Size])
    return ret

def get_feature_from_load_config( pe ) :
    LOAD_CONFIG = ['CSDVersion', 'CriticalSectionDefaultTimeout', 'DeCommitFreeBlockThreshold', 'DeCommitTotalFreeThreshold', 'EditList',
                   'GlobalFlagsClear','GlobalFlagsSet','GuardCFCheckFunctionPointer','GuardCFFunctionCount','GuardCFFunctionTable', 'GuardFlags',
                   'LockPrefixTable', 'MajorVersion', 'MaximumAllocationSize', 'MinorVersion', 'ProcessAffinityMask', 'ProcessHeapFlags',
                   'Reserved1', 'Reserved2', 'SEHandlerCount', 'SEHandlerTable', 'SecurityCookie', 'Size', 'TimeDateStamp', 'VirtualMemoryThreshold']
    ret = dict()
    if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') and hasattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG, 'struct') :
        for each in LOAD_CONFIG :
            ret[each] = getattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct, each, None)
    return ret


def get_feature_from_tls( pe ) :
    TLS = ['AddressOfCallBacks', 'AddressOfIndex', 'Characteristics', 'EndAddressOfRawData', 'SizeOfZeroFill', 'StartAddressOfRawData']
    ret = dict()
    if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and hasattr(pe.DIRECTORY_ENTRY_TLS, 'struct') and hasattr(pe.DIRECTORY_ENTRY_TLS.struct, 'AddressOfCallBacks'):
        for each in TLS :
            ret[each] = getattr(pe.DIRECTORY_ENTRY_TLS.struct, each, None)
        ret['callbacks'] = []
        callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
        idx = 0
        while True:
            func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
            if func == 0:
                break
            ret['callbacks'].append(func)
            idx += 1
    return ret

def get_feature_from_file_info( pe ) :
    ret = list()
    if hasattr(pe, 'FileInfo') :
        for e in pe.FileInfo :
            for fileinfo in e :
                if fileinfo.Key == b'StringFileInfo':
                    each = dict()
                    for st in fileinfo.StringTable:
                        for key, value in st.entries.items():
                            if isinstance(key, bytes) :
                                key = key.decode().strip(' \t\r\n\0')
                            if isinstance(value, bytes) :
                                value = value.decode().strip(' \t\r\n\0')

                            each[key] = value
                    if len(each) != 0 :
                        ret.append(each)

                if fileinfo.Key == b'VarFileInfo':
                    each = dict()
                    for var in fileinfo.Var:
                        for key, value in var.entry.items() :
                            if isinstance(key, bytes):
                                key = key.decode().strip(' \t\r\n\0')
                            if isinstance(value, bytes):
                                value = value.decode().strip(' \t\r\n\0')
                            each[key]=value
                    if len(each) != 0 :
                        ret.append(each)
    return ret

def get_feature_from_debug( pe ) :
    DEBUG = ['Characteristics', 'TimeDateStamp', 'MajorVersion', 'MinorVersion', 'Type'
             'SizeOfData', 'AddressOfRawData', 'PointerToRawData']
    CV_INFO_PDB20 = ['CvHeaderSignature', 'CvHeaderOffset', 'Signature', 'Age']
    CV_INFO_PDB70 = ['CvSignature', 'Signature_Data1', 'Signature_Data2', 'Signature_Data3', 'Signature_Data4', 'Signature_Data5', 'Signature_Data6', 'Age']
    ret = []
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') :
        for debug in pe.DIRECTORY_ENTRY_DEBUG :
            each_debug = dict()
            for each in DEBUG :
                each_debug[each] = getattr(debug.struct, each, None)
            if debug.entry :
                each_debug['entry'] = dict()
                if debug.entry.name == 'CV_INFO_PDB20' :
                    each_debug['entry']['name'] = 'CV_INFO_PDB20'
                    for key in CV_INFO_PDB20 :
                        each_debug['entry'][key] = getattr(debug.entry, key, None)
                    each_debug['entry']['PdbFileName'] = debug.entry.PdbFileName.decode().strip(' \t\r\n\0')
                elif debug.entry.name == 'CV_INFO_PDB70' :
                    each_debug['entry']['name'] = 'CV_INFO_PDB70'
                    for key in CV_INFO_PDB70 :
                        each_debug['entry'][key] = getattr(debug.entry, key, None)
                    each_debug['entry']['PdbFileName'] = debug.entry.PdbFileName.decode().strip(' \t\r\n\0')
            ret.append(each_debug)
    return ret

def get_feature_from_basereloc( pe ) :
    ret = []
    BASE_RELOCATION = ['VirtualAddress', 'SizeOfBlock']
    RELOCATION = ['base_rva', 'rva', 'type']
    if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC') :
        for base_relocation_data in pe.DIRECTORY_ENTRY_BASERELOC :
            data = dict()
            for each in BASE_RELOCATION :
                data[each] = getattr(base_relocation_data.struct, each, None)
            if base_relocation_data.entries :
                data['entries'] = []
                for relocation_data in base_relocation_data.entries :
                    data2 = dict()
                    for each2 in RELOCATION :
                        data2[each2] = getattr(relocation_data, each2, None)
                    data2['Data'] = getattr(relocation_data.struct, 'Data', None)
                    data['entries'].append(data2)
            ret.append(data)
    return ret

def get_asm ( pe ) :
    try :
        machine_bit = pe.FILE_HEADER.Machine
        ret = {}
        if machine_bit == 0x014c :
            dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            for section in pe.sections :
                if section.Characteristics & 0x00000020 == 0x00000020 and section.Characteristics & 0x20000000 and section.Characteristics & 0x40000000 ==  0x40000000 :
                    scn = section.Name.decode().strip(' \t\r\n\0')
                    ret[scn] = []
                    for i in dis.disasm(section.get_data(), 0x1000) :
                        ret[scn].append([i.address, " ".join([format(i, '02x') for i in i.bytes]), "{} {}".format(i.mnemonic, i.op_str).strip()])
        return ret
    except :
        return {}


def get_certificate( pe ) :
    certs = []
    try:
        dir_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[dir_index]
        if not dir_entry or not dir_entry.VirtualAddress or not dir_entry.Size:
            return certs
        else:
            signatures = pe.write()[dir_entry.VirtualAddress + 8:]
            bio = M2Crypto.BIO.MemoryBuffer(bytes(signatures))
            if not bio:
                return certs
            else:
                pkcs7_obj = M2Crypto.m2.pkcs7_read_bio_der(bio.bio_ptr())
                if not pkcs7_obj:
                    return certs
                else:
                    certs = []
                    p7 = M2Crypto.SMIME.PKCS7(pkcs7_obj)
                    for cert in p7.get0_signers(M2Crypto.X509.X509_Stack()):
                        subject = cert.get_subject()
                        certs.append({
                            "serial_number": "%032x" % cert.get_serial_number(),
                            "common_name": subject.CN,
                            "country": subject.C,
                            "locality": subject.L,
                            "organization": subject.O,
                            #"email": subject.Email,
                            "sha1": "%040x" % int(cert.get_fingerprint("sha1"), 16),
                            "md5": "%032x" % int(cert.get_fingerprint("md5"), 16),
                        })
                        if subject.GN and subject.SN:
                            certs[-1]["full_name"] = "%s %s" % (subject.GN, subject.SN)
                        elif subject.GN:
                            certs[-1]["full_name"] = subject.GN
                        elif subject.SN:
                            certs[-1]["full_name"] = subject.SN
    except:
        return certs

def run( file_path ) :
    with open(file_path, 'rb') as f :
        file_data = f.read()

    pe = pefile.PE( data = file_data )
    json_obj = dict()

    # File Name
    json_obj['name'] = os.path.basename(file_path)

    # Dll
    json_obj['dll'] = pe.is_dll()

    # Hash
    json_obj['hash'] = dict()
    ## Cryptographic Hash
    json_obj['hash']['md5'], json_obj['hash']['sha1'], json_obj['hash']['sha256'] = get_hash(file_path)

    # Magic
    json_obj['file_type'] = magic.from_file(file_path)

    # File Size
    json_obj['file_size'] = os.path.getsize(file_path)

    # String
    json_obj['string'] = get_string(file_data)

    # PE Info
    json_obj['pe_info'] = dict()
    ## Imphash
    json_obj['pe_info']['imphash'] = get_imphash(pe)
    ## From File Header
    json_obj['pe_info']['file_header'] = get_feature_from_file_header( pe )
    ## From Optional Header
    json_obj['pe_info']['optional_header'] = get_feature_from_optional_header( pe )
    ## From Data Directory
    json_obj['pe_info']['data_directory'] = get_feature_from_data_directory( pe )
    ## From IAT
    json_obj['pe_info']['import'] = get_import_function( pe )
    ## From EAT
    json_obj['pe_info']['export'] = get_export_function( pe )
    ## From Res
    json_obj['pe_info']['resource'] = get_resources_info( pe )
    ## From Load Config
    json_obj['pe_info']['load_config'] = get_feature_from_load_config( pe )
    ## From TLS
    json_obj['pe_info']['tls'] = get_feature_from_tls( pe )
    ## From File Info
    json_obj['pe_info']['file_info'] = get_feature_from_file_info( pe )
    ## From Debug
    json_obj['pe_info']['debug'] = get_feature_from_debug( pe )
    ## From BaseRelocation
    json_obj['pe_info']['basereloc'] = get_feature_from_basereloc( pe )
    ## Sertificate
    json_obj['pe_info']['certificate'] = get_certificate(pe)

    ## Packer Info
    json_obj['pe_info']['packer_info'] = get_packer_info(pe)

    ## Disasm
    json_obj['disasm'] = get_asm( pe )
    # Yara
    #json_obj['yara'] = dict()
    ## Anti Debugging
    #json_obj['yara']['anti_debug_info'] = get_anti_debug_info( file_data )

    # Fuzzy Hash
    json_obj['fuzzy_hash'] = get_fuzzy_hash( file_data )

    # Save report file
    with open("{}.json".format(json_obj['hash']['md5']), 'w') as f :
        json.dump(json_obj, f, indent=4)

if __name__ == '__main__' :
    if len(sys.argv) == 1 :
        print_help()
        exit(0)
    if len(sys.argv) == 2 :
        file_path = sys.argv[1]
        if isfile(file_path) :
            run(file_path)
