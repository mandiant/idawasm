import struct

import wasm
import wasm.decode
import wasm.wasmtypes

import idc
import idaapi

import idawasm.const


def accept_file(f, n):
    f.seek(0)
    if f.read(4) != b'\x00asm':
        return 0

    if struct.unpack('<I', f.read(4))[0] != 0x1:
        return 0

    return 'WebAssembly v%d executable' % (0x1)


def offset_of(struc, fieldname):
    p = 0
    dec_meta = struc.get_decoder_meta()
    for field in struc.get_meta().fields:
        if field.name != fieldname:
            p += dec_meta['lengths'][field.name]
        else:
            return p
    raise KeyError('field not found: ' + fieldname)


def size_of(struc, fieldname=None):
    if fieldname is not None:
        # size of the given field, by name
        dec_meta = struc.get_decoder_meta()
        return dec_meta['lengths'][fieldname]
    else:
        # size of the entire given struct
        return sum(struc.get_decoder_meta()['lengths'].values())


import collections
Field = collections.namedtuple('Field', ['offset', 'name', 'size'])

def get_fields(struc):
    p = 0
    dec_meta = struc.get_decoder_meta()
    for field in struc.get_meta().fields:
        flen = dec_meta['lengths'][field.name]
        if flen > 0:
            yield Field(p, field.name, flen)
        p += flen


def MakeN(addr, size):
    if size == 1:
        idc.MakeByte(addr)
    elif size == 2:
        idc.MakeWord(addr)
    elif size == 4:
        idc.MakeDword(addr)
    elif size == 8:
        idc.MakeQword(addr)


def get_section(sections, section_id):
    for i, section in enumerate(sections):
        if i == 0:
            continue

        if section.data.id != section_id:
            continue

        return section


def load_code_section(section, p):
    idc.MakeName(p + offset_of(section.data, 'id'), 'code_id')
    MakeN(p + offset_of(section.data, 'id'), size_of(section.data, 'id'))

    ppayload = p + offset_of(section.data, 'payload')
    idc.MakeName(ppayload + offset_of(section.data.payload, 'count'), 'function_count')
    MakeN(ppayload + offset_of(section.data.payload, 'count'), size_of(section.data.payload, 'count'))

    pbodies = ppayload + offset_of(section.data.payload, 'bodies')
    pcur = pbodies
    for i, body in enumerate(section.data.payload.bodies):
        fname = 'function_%X' % (i)
        idc.MakeName(pcur, fname + '_meta')

        idc.MakeName(pcur + offset_of(body, 'local_count'), fname + '_local_count')
        MakeN(pcur + offset_of(body, 'local_count'), size_of(body, 'local_count'))

        if size_of(body, 'locals') > 0:
            idc.MakeName(pcur + offset_of(body, 'locals'), fname + '_locals')
            for j in range(size_of(body, 'locals')):
                idc.MakeByte(pcur + offset_of(body, 'locals') + j)

        pcode = pcur + offset_of(body, 'code')
        idc.MakeName(pcode, fname)
        idc.MakeCode(pcode)
        idc.MakeFunction(pcode)

        pcur += size_of(body)


def load_globals_section(section, p):
    idc.MakeName(p + offset_of(section.data, 'id'), 'globals_id')
    MakeN(p + offset_of(section.data, 'id'), size_of(section.data, 'id'))

    idc.MakeName(p + offset_of(section.data, 'payload_len'), 'globals_size')
    MakeN(p + offset_of(section.data, 'payload_len'), size_of(section.data, 'payload_len'))

    ppayload = p + offset_of(section.data, 'payload')
    idc.MakeName(ppayload + offset_of(section.data.payload, 'count'), 'globals_count')
    MakeN(ppayload + offset_of(section.data.payload, 'count'), size_of(section.data.payload, 'count'))

    pglobals = ppayload + offset_of(section.data.payload, 'globals')
    pcur = pglobals
    for i, body in enumerate(section.data.payload.globals):
        gname = 'global_%X' % (i)

        ptype = pcur + offset_of(body, 'type')
        idc.MakeName(ptype + offset_of(body.type, 'content_type'), gname + '_content_type')
        MakeN(ptype + offset_of(body.type, 'content_type'), size_of(body.type, 'content_type'))
        ctype = idawasm.const.WASM_TYPE_NAMES[body.type.content_type]
        idaapi.append_cmt(ptype + offset_of(body.type, 'content_type'), ctype, False)

        idc.MakeName(ptype + offset_of(body.type, 'mutability'), gname + '_mutability')
        MakeN(ptype+ offset_of(body.type, 'mutability'), size_of(body.type, 'mutability'))

        # we need a target that people can rename.
        # so lets map `global_N` to the init expr field.
        # this will look like:
        #
        #     global_0        <---- named address we can reference
        #     global_0_init:  <---- fake label line
        #        i32.const    <---- init expression insns
        #        ret
        pinit = pcur + offset_of(body, 'init')
        idc.MakeName(pinit, gname)
        idc.ExtLinA(pinit, 0, gname + '_init:')
        idc.MakeCode(pinit)

        pcur += size_of(body)



SECTION_LOADERS = {
    wasm.wasmtypes.SEC_CODE: load_code_section,
    wasm.wasmtypes.SEC_GLOBAL: load_globals_section,
}


def compute_global_addrs(sections):
    ret = []
    section = get_section(sections, wasm.wasmtypes.SEC_GLOBAL)
    ppayload = p + offset_of(section.data, 'payload')
    pglobals = ppayload + offset_of(section.data.payload, 'globals')
    pcur = pglobals
    for i, body in enumerate(section.data.payload.globals):
        ret.append(pcur + offset_of(body, 'init'))
        pcur += size_of(body)


def compute_function_addrs(sections):
    ret = []
    section = get_section(sections, wasm.wasmtypes.SEC_FUNCTION)
    ppayload = p + offset_of(section.data, 'payload')
    pbodies = ppayload + offset_of(section.data.payload, 'bodies')
    pcur = pbodies
    for i, body in enumerate(section.data.payload.bodies):
        pcode = pcur + offset_of(body, 'code')
        ret.append({
            'index': i,
            'addr': pcode,
            'body': body,
        })
        pcur += size_of(body)


def load_file(f, neflags, format):
    f.seek(0x0, os.SEEK_END)
    flen = f.tell()
    f.seek(0x0)
    buf = f.read(flen)

    idaapi.set_processor_type('wasm', idaapi.SETPROC_ALL)

    f.seek(0x0)
    f.file2base(0, 0, len(buf), True)

    p = 0
    sections = wasm.decode.decode_module(buf)
    for i, section in enumerate(sections):
        if i == 0:
            sname = 'header'
        else:
            if section.data.id == 0:
                # fetch custom name
                sname = ''
            else:
                sname = idawasm.const.WASM_SECTION_NAMES.get(section.data.id, 'unknown')

        if sname != 'header' and section.data.id in (wasm.wasmtypes.SEC_CODE, wasm.wasmtypes.SEC_GLOBAL):
            stype = 'CODE'
        else:
            stype = 'DATA'

        slen = sum(section.data.get_decoder_meta()['lengths'].values())
        idaapi.add_segm(0, p, p + slen, sname, stype)

        if sname != 'header':
            loader = SECTION_LOADERS.get(section.data.id)
            if loader is not None:
                loader(section, p)

        p += slen

    # magic
    idc.MakeDword(0x0)
    idc.MakeName(0x0, 'WASM_MAGIC')
    # version
    idc.MakeDword(0x4)
    idc.MakeName(0x4, 'WASM_VERSION')

    return 1
