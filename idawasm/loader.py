import os
import struct

import wasm
import wasm.decode
import wasm.wasmtypes

import idc
import idaapi

import idawasm.const
import idawasm.common


def accept_file(f, n):
    '''
    return the name of the format, if it looks like a WebAssembly module, or 0 on unsupported.

    Args:
      f (file): the file to inspect.
      n (any): unused.

    Returns:
      Union[str, int]: str if supported, 0 if unsupported.
    '''
    f.seek(0)
    if f.read(4) != b'\x00asm':
        return 0

    if struct.unpack('<I', f.read(4))[0] != 0x1:
        # only support v1 right now
        return 0

    return 'WebAssembly v%d executable' % (0x1)


def MakeN(addr, size):
    '''
    Make a integer with the given size at the given address.

    Args:
      addr (int): effective address.
      size (int): the size of the integer, one of 1, 2, 4, or 8.
    '''
    if size == 1:
        idc.MakeByte(addr)
    elif size == 2:
        idc.MakeWord(addr)
    elif size == 4:
        idc.MakeDword(addr)
    elif size == 8:
        idc.MakeQword(addr)


def get_section(sections, section_id):
    '''
    given a sequence of sections, return the section with the given id.
    '''
    for i, section in enumerate(sections):
        if i == 0:
            continue

        if section.data.id != section_id:
            continue

        return section


def format_value(name, value):
    '''
    format the given value into something human readable, using the given name as a hint.

    Example::

        assert format_value('sections:11:payload_len', 0x23) == '0x23'

    Example::

        assert format_value('sections:1:payload:entries:0:param_types', [-1, -1, -1]) == '[i32, i32, i32]'

    Args:
      name (str): the structure property name.
      value (Any): the value to format.

    Returns:
      str: a string formatted for human consumption.
    '''
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
    '''
    Load the given structure into the current IDA Pro at the given offset.

    Example::

        load_struc(sections[0].data, 0x0, 'foo-section')

    Args:
      struc (wasm.Structure): the structure to load.
      p (int): the effective address at which to load.
      path (str): the namespaced name of the given structure.

    Returns:
      int: the next offset following the loaded structure.
    '''
    for field in idawasm.common.get_fields(struc):
        # build names like: `sections:2:payload:entries:0:module_str`
        name = path + ':' + field.name

        # recurse into nested structures
        if idawasm.common.is_struc(field.value):
            p = load_struc(field.value, p, name)

        # recurse into lists of structures
        elif (isinstance(field.value, list)
              and len(field.value) > 0
              and idawasm.common.is_struc(field.value[0])):

            for i, v in enumerate(field.value):
                p = load_struc(v, p, name + ':' + str(i))

        # emit primitive types
        else:
            # add annotations like follows:
            #
            #     imports:002D sections:2:payload:entries:0:module_len         <--- Add line prior to element.
            #     imports:002D                 db 3                    ;; 0x3  <--- Render element for human.
            #     imports:002E sections:2:payload:entries:0:module_str
            #     imports:002E                 db 0x65 ;; e            ;; env  <--- Pull out strings and lists nicely.
            #     imports:002F                 db 0x6E ;; n
            #     imports:0030                 db 0x76 ;; v

            # add line prior to element
            idc.ExtLinA(p, 0, name)

            # if primitive integer element, set it as such
            if isinstance(field.value, int):
                MakeN(p, field.size)

            # add comment containing human-readable representation
            idc.MakeComm(p, format_value(name, field.value).encode('utf-8'))

            p += field.size

    return p


def load_section(section, p):
    '''
    Load the given section into the current IDA Pro at the given offset.

    Example::

        load_section(sections[0], 0x0)

    Args:
      struc (wasm.Structure): the structure to load.
      p (int): the effective address at which to load.

    Returns:
      int: the next offset following the loaded structure.
    '''
    load_struc(section.data, p, 'sections:' + str(section.data.id))


def load_globals_section(section, p):
    '''
    Specialized handler for the GLOBALS section to mark the initializer as code.
    '''
    ppayload = p + idawasm.common.offset_of(section.data, 'payload')
    pglobals = ppayload + idawasm.common.offset_of(section.data.payload, 'globals')
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
        pinit = pcur + idawasm.common.offset_of(body, 'init')
        idc.MakeName(pinit, gname)
        idc.ExtLinA(pinit, 0, gname + '_init:')
        idc.MakeCode(pinit)

        pcur += idawasm.common.size_of(body)


def load_elements_section(section, p):
    '''
    Specialized handler for the ELEMENTS section to mark the offset initializer as code.
    '''
    ppayload = p + idawasm.common.offset_of(section.data, 'payload')
    pentries = ppayload + idawasm.common.offset_of(section.data.payload, 'entries')
    pcur = pentries
    for i, body in enumerate(section.data.payload.entries):
        idc.MakeCode(pcur + idawasm.common.offset_of(body, 'offset'))
        pcur += idawasm.common.size_of(body)


def load_data_section(section, p):
    '''
    specialized handler for the DATA section to mark the offset initializer as code.
    '''
    ppayload = p + idawasm.common.offset_of(section.data, 'payload')
    pentries = ppayload + idawasm.common.offset_of(section.data.payload, 'entries')
    pcur = pentries
    for i, body in enumerate(section.data.payload.entries):
        idc.MakeCode(pcur + idawasm.common.offset_of(body, 'offset'))
        pcur += idawasm.common.size_of(body)


SECTION_LOADERS = {
    wasm.wasmtypes.SEC_GLOBAL: load_globals_section,
    wasm.wasmtypes.SEC_ELEMENT: load_elements_section,
    wasm.wasmtypes.SEC_DATA: load_data_section,
}


def load_file(f, neflags, format):
    '''
    load the given file into the current IDA Pro database.

    Args:
      f (file): the file-like object to load.
      neflags (Any): unused
      format (Any): unused

    Returns:
      int: 1 on success, 0 on failure
    '''

    # compute file size, then read the entire contents
    f.seek(0x0, os.SEEK_END)
    flen = f.tell()
    f.seek(0x0)
    buf = f.read(flen)

    # mark the proc type, so IDA can invoke the correct disassembler/processor.
    # this must match `processor.wasm_processor_t.psnames`
    idaapi.set_processor_type('wasm', idaapi.SETPROC_ALL)

    f.seek(0x0)
    # load the entire file directly at address zero.
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

        # add IDA segment with type, name, size as appropriate
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
