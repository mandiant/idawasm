import os
import struct

import wasm
import wasm.decode
import wasm.wasmtypes

import idc
import idaapi

import idawasm.const
from idawasm.common import *


def accept_file(f, n):
    f.seek(0)
    if f.read(4) != b'\x00asm':
        return 0

    if struct.unpack('<I', f.read(4))[0] != 0x1:
        # only support v1 right now
        return 0

    return 'WebAssembly v%d executable' % (0x1)


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


def is_struc(o):
    return  '.GeneratedStructureData' in str(type(o))


def format_value(name, value):
    if isinstance(value, int):
        # a heuristic to detect fields that contain a type value
        if 'type' in name or 'form' in name:
            try:
                return idawasm.const.WASM_TYPE_NAMES[value]
            except KeyError:
                return hex(value)
        else:
            return hex(value)
    elif isinstance(value, list):
        return '[' + ', '.join([format_value(name, v) for v in value]) + ']'
    elif isinstance(value, memoryview) and 'str' in name:
        try:
            return value.tobytes().decode('utf-8')
        except UnicodeDecodeError:
            return ''
    else:
        return ''


def load_struc(struc, p, path):
    for field in get_fields(struc):
        name = path + ':' + field.name
        if is_struc(field.value):
            p = load_struc(field.value, p, name)
        elif isinstance(field.value, list) and len(field.value) > 0 and is_struc(field.value[0]):
            for i, v in enumerate(field.value):
                p = load_struc(v, p, name + ':' + str(i))
        else:
            idc.ExtLinA(p, 0, name)
            if isinstance(field.value, int):
                MakeN(p, field.size)
            idc.MakeComm(p, format_value(name, field.value).encode('utf-8'))
            p += field.size

    return p


def load_section(section, p):
    load_struc(section.data, p, 'sections:' + str(section.data.id))


def load_globals_section(section, p):
    '''
    specialized handler for the globals section to mark the initializer as code.
    '''
    ppayload = p + offset_of(section.data, 'payload')
    pglobals = ppayload + offset_of(section.data.payload, 'globals')
    pcur = pglobals
    for i, body in enumerate(section.data.payload.globals):
        gname = 'global_%X' % (i)
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


def load_elements_section(section, p):
    '''
    specialized handler for the elements section to mark the offset initializer as code.
    '''
    ppayload = p + offset_of(section.data, 'payload')
    pentries = ppayload + offset_of(section.data.payload, 'entries')
    pcur = pentries
    for i, body in enumerate(section.data.payload.entries):
        idc.MakeCode(pcur + offset_of(body, 'offset'))
        pcur += size_of(body)


def load_data_section(section, p):
    '''
    specialized handler for the data section to mark the offset initializer as code.
    '''
    ppayload = p + offset_of(section.data, 'payload')
    pentries = ppayload + offset_of(section.data.payload, 'entries')
    pcur = pentries
    for i, body in enumerate(section.data.payload.entries):
        idc.MakeCode(pcur + offset_of(body, 'offset'))
        pcur += size_of(body)



SECTION_LOADERS = {
    wasm.wasmtypes.SEC_GLOBAL: load_globals_section,
    wasm.wasmtypes.SEC_ELEMENT: load_elements_section,
    wasm.wasmtypes.SEC_DATA: load_data_section,
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

            load_section(section, p)

        p += slen

    # magic
    idc.MakeDword(0x0)
    idc.MakeName(0x0, 'WASM_MAGIC')
    # version
    idc.MakeDword(0x4)
    idc.MakeName(0x4, 'WASM_VERSION')

    return 1
