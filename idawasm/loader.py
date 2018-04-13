import idc
import idaapi

import struct

import wasm
import wasm.decode


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
        slen = sum(section.data.get_decoder_meta()['lengths'].values())
        idaapi.add_segm(0, p, p + slen, str(i), "DATA")
        p += slen

    # magic
    idc.MakeDword(0x0)
    idc.MakeName(0x0, "WASM_MAGIC")
    # version
    idc.MakeDword(0x4)
    idc.MakeName(0x4, "WASM_VERSION")

    return 1
