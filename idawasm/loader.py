import struct

import wasm
import wasm.decode
import wasm.wasmtypes

import idc
import idaapi


SECTION_NAMES = {
    wasm.wasmtypes.SEC_TYPE: "types",
    wasm.wasmtypes.SEC_IMPORT: "imports",
    wasm.wasmtypes.SEC_FUNCTION: "functions",
    wasm.wasmtypes.SEC_TABLE: "tables",
    wasm.wasmtypes.SEC_MEMORY: "memory",
    wasm.wasmtypes.SEC_GLOBAL: "globals",
    wasm.wasmtypes.SEC_EXPORT: "exports",
    wasm.wasmtypes.SEC_START: "starts",
    wasm.wasmtypes.SEC_ELEMENT: "elements",
    wasm.wasmtypes.SEC_CODE: "code",
    wasm.wasmtypes.SEC_DATA: "data",
}


def accept_file(f, n):
    f.seek(0)
    if f.read(4) != b"\x00asm":
        return 0

    if struct.unpack("<I", f.read(4))[0] != 0x1:
        return 0

    return "WebAssembly v%d executable" % (0x1)


def load_file(f, neflags, format):
    f.seek(0x0, os.SEEK_END)
    flen = f.tell()
    f.seek(0x0)
    buf = f.read(flen)

    # TODO: need to provide a wasm processor
    idaapi.set_processor_type("8086", idaapi.SETPROC_ALL)

    f.seek(0x0)
    f.file2base(0, 0, len(buf), True)

    p = 0
    sections = wasm.decode.decode_module(buf)
    for i, section in enumerate(sections):
        if i == 0:
            sname = 'header'
            stype = 'DATA'
        else:
            if section.data.id == 0:
                # fetch custom name
                sname = ''
                stype = 'DATA'
            else:
                sname = SECTION_NAMES.get(section.data.id, 'unknown')
                stype = 'CODE'

        slen = sum(section.data.get_decoder_meta()['lengths'].values())
        idaapi.add_segm(0, p, p + slen, sname, stype)
        p += slen

    # magic
    idc.MakeDword(0x0)
    idc.MakeName(0x0, "WASM_MAGIC")
    # version
    idc.MakeDword(0x4)
    idc.MakeName(0x4, "WASM_VERSION")

    return 1
