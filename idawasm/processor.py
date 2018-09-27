# TODO:
#  - name locations
#  - mark data xref to memory load/store
#  - mark xref to imports
#  - compute stack deltas
#  - add entry point for start function (need to see an example)

# stdlib
import logging
import functools

# from pip
import wasm
import wasm.wasmtypes

# from IDA
import idc
import idaapi
import idautils

# from this project
import idawasm.const
import idawasm.common
import idawasm.analysis.llvm


logger = logging.getLogger(__name__)


# these are wasm-specific operand types
WASM_LOCAL = idaapi.o_idpspec0
WASM_GLOBAL = idaapi.o_idpspec1
WASM_FUNC_INDEX = idaapi.o_idpspec2
WASM_TYPE_INDEX = idaapi.o_idpspec3
WASM_BLOCK = idaapi.o_idpspec4
WASM_ALIGN = idaapi.o_idpspec5


def no_exceptions(f):
    '''
    decorator that catches and logs any exceptions.
    the exceptions are swallowed, and `0` is returned.

    this is useful for routines that IDA invokes, as IDA bails on exceptions.

    Example::

        @no_exceptions
        def definitely_doesnt_work():
            raise ZeroDivisionError()

        assert definitely_doesnt_work() == 0
    '''
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        # we explicitly want to catch all exceptions here,
        # because IDA cannot handle them.
        except:  # NOQA: E722 do not use bare 'except'
            logger.error('exception in %s', f.__name__, exc_info=True)
            return 0
    return wrapper


# tags functions that are invoked from IDA-land.
ida_entry = no_exceptions


class wasm_processor_t(idaapi.processor_t):
    # processor ID for the wasm disassembler.
    # I made this number up.
    id = 0x8069
    flag = idaapi.PR_USE32 | idaapi.PR_RNAMESOK | idaapi.PRN_HEX | idaapi.PR_NO_SEGMOVE
    cnbits = 8
    dnbits = 8
    psnames = ['wasm']
    plnames = ['WebAssembly']
    segreg_size = 0
    tbyte_size = 0
    assembler = {
        'flag': idaapi.ASH_HEXF3 | idaapi.AS_UNEQU | idaapi.AS_COLON | idaapi.ASB_BINF4 | idaapi.AS_N2CHR,
        'uflag': 0,
        'name': "WebAssembly assembler",
        'origin': "org",
        'end': "end",
        'cmnt': ";;",
        'ascsep': "\"",
        'accsep': "'",
        'esccodes': "\"'",
        'a_ascii': "db",
        'a_byte': "db",
        'a_word': "dw",
        'a_dword': "dd",
        'a_qword': "dq",
        'a_oword': "xmmword",
        'a_float': "dd",
        'a_double': "dq",
        'a_tbyte': "dt",
        'a_dups': "#d dup(#v)",
        'a_bss': "%s dup ?",
        'a_seg': "seg",
        'a_curip': "$",
        'a_public': "public",
        'a_weak': "weak",
        'a_extrn': "extrn",
        'a_comdef': "",
        'a_align': "align",
        'lbrace': "(",
        'rbrace': ")",
        'a_mod': "%",
        'a_band': "&",
        'a_bor': "|",
        'a_xor': "^",
        'a_bnot': "~",
        'a_shl': "<<",
        'a_shr': ">>",
        'a_sizeof_fmt': "size %s",
    }

    def dt_to_width(self, dt):
        '''
        returns OOFW_xxx flag given a dt_xxx
        '''
        return {
            idaapi.dt_byte:  idaapi.OOFW_8,
            idaapi.dt_word:  idaapi.OOFW_16,
            idaapi.dt_dword: idaapi.OOFW_32,
            idaapi.dt_qword: idaapi.OOFW_64,
        }[dt]

    def _get_section(self, section_id):
        '''
        fetch the section with the given id.

        Args:
          section_id (int): the section id.

        Returns:
          wasm.Structure: the section.

        Raises:
          KeyError: if the section is not found.
        '''
        for i, section in enumerate(self.sections):
            if i == 0:
                continue

            if section.data.id != section_id:
                continue

            return section

        raise KeyError(section_id)

    def _get_section_offset(self, section_id):
        '''
        fetch the file offset of the given section.

        Args:
          section_id (int): the section id.

        Returns:
          int: the offset of the section.

        Raises:
          KeyError: if the section is not found.
        '''
        p = 0
        for i, section in enumerate(self.sections):
            if i == 0:
                p += idawasm.common.size_of(section.data)
                continue

            if section.data.id != section_id:
                p += idawasm.common.size_of(section.data)
                continue

            return p

        raise KeyError(section_id)

    def _compute_function_branch_targets(self, offset, code):
        '''
        compute branch targets for the given code segment.

        we can do it in a single pass:
        scan instructions, tracking new blocks, and maintaining a stack of nested blocks.
        when we hit a branch instruction, use the stack to resolve the branch target.
        the branch target will always come from the enclosing scope.

        Args:
          offset (int): offset of the given code segment.
          code (bytes): raw bytecode.

        Returns:
          Dict[int, Dict[int, int]]: map from instruction addresses to map from relative depth to branch target address.
        '''
        # map from virtual address to map from relative depth to virtual address
        branch_targets = {}
        # map from block index to block instance, with fields including `offset` and `depth`
        blocks = {}
        # stack of block indexes
        block_stack = []
        p = offset

        for bc in wasm.decode.decode_bytecode(code):
            if bc.op.id in {wasm.opcodes.OP_BLOCK, wasm.opcodes.OP_LOOP, wasm.opcodes.OP_IF}:
                # enter a new block, so capture info, and push it onto the current depth stack
                block_index = len(blocks)
                block = {
                    'index': block_index,
                    'offset': p,
                    'depth': len(block_stack),
                    'type': {
                        wasm.opcodes.OP_BLOCK: 'block',
                        wasm.opcodes.OP_LOOP: 'loop',
                        wasm.opcodes.OP_IF: 'if',
                    }[bc.op.id],
                }
                blocks[block_index] = block
                block_stack.insert(0, block_index)
                branch_targets[p] = {
                    # reference to block that is starting
                    'block': block
                }

            elif bc.op.id in {wasm.opcodes.OP_END}:
                if len(block_stack) == 0:
                    # end of function
                    branch_targets[p] = {
                        'block': {
                            'type': 'function',
                            'offset': offset,     # start of function
                            'end_offset': p,      # end of function
                            'depth': 0,           # top level always has depth 0
                        }
                    }
                    break

                # leaving a block, so pop from the depth stack
                block_index = block_stack.pop(0)
                block = blocks[block_index]
                block['end_offset'] = p + bc.len
                branch_targets[p] = {
                    # reference to block that is ending
                    'block': block
                }

            elif bc.op.id in {wasm.opcodes.OP_BR, wasm.opcodes.OP_BR_IF}:
                block_index = block_stack[bc.imm.relative_depth]
                block = blocks[block_index]
                branch_targets[p] = {
                    bc.imm.relative_depth: block
                }

            elif bc.op.id in {wasm.opcodes.OP_ELSE}:
                # TODO: not exactly sure of the semantics here
                raise NotImplementedError('else')

            elif bc.op.id in {wasm.opcodes.OP_BR_TABLE}:
                # TODO: not exactly sure what one of these looks like yet.
                raise NotImplementedError('br table')
                # probably will populate `branch_targets` with multiple entries

            p += bc.len

        return branch_targets

    def _compute_branch_targets(self):
        branch_targets = {}

        code_section = self._get_section(wasm.wasmtypes.SEC_CODE)
        pcode_section = self._get_section_offset(wasm.wasmtypes.SEC_CODE)

        ppayload = pcode_section + idawasm.common.offset_of(code_section.data, 'payload')
        pbody = ppayload + idawasm.common.offset_of(code_section.data.payload, 'bodies')
        for body in code_section.data.payload.bodies:
            pcode = pbody + idawasm.common.offset_of(body, 'code')
            branch_targets.update(self._compute_function_branch_targets(pcode, body.code))
            pbody += idawasm.common.size_of(body)

        return branch_targets

    def _parse_types(self):
        '''
        parse the type entries.

        Returns:
          List[Dict[str, Any]]: list if type descriptors, each which hash:
            - form
            - param_count
            - param_types
            - return_count
            - return_type
        '''
        type_section = self._get_section(wasm.wasmtypes.SEC_TYPE)
        return idawasm.common.struc_to_dict(type_section.data.payload.entries)

    def _parse_globals(self):
        '''
        parse the global entries.

        Returns:
          Dict[int, Dict[str, any]]: from global index to dict with keys `offset` and `type`.
        '''
        globals_ = {}
        global_section = self._get_section(wasm.wasmtypes.SEC_GLOBAL)
        pglobal_section = self._get_section_offset(wasm.wasmtypes.SEC_GLOBAL)

        ppayload = pglobal_section + idawasm.common.offset_of(global_section.data, 'payload')
        pglobals = ppayload + idawasm.common.offset_of(global_section.data.payload, 'globals')
        pcur = pglobals
        for i, body in enumerate(global_section.data.payload.globals):
            pinit = pcur + idawasm.common.offset_of(body, 'init')
            ctype = idawasm.const.WASM_TYPE_NAMES[body.type.content_type]
            globals_[i] = {
                'index': i,
                'offset': pinit,
                'type': ctype,
            }
            pcur += idawasm.common.size_of(body)
        return globals_

    def _parse_imported_functions(self):
        '''
        parse the import entries for functions.
        useful for recovering function names.

        Returns:
          Dict[int, Dict[str, any]]: from function index to dict with keys `index`, `module`, and `name`.
        '''
        functions = {}
        import_section = self._get_section(wasm.wasmtypes.SEC_IMPORT)
        type_section = self._get_section(wasm.wasmtypes.SEC_TYPE)

        function_index = 0
        for entry in import_section.data.payload.entries:
            if entry.kind != idawasm.const.WASM_EXTERNAL_KIND_FUNCTION:
                continue

            type_index = entry.type.type
            ftype = type_section.data.payload.entries[type_index]

            functions[function_index] = {
                'index': function_index,
                'module': entry.module_str.tobytes().decode('utf-8'),
                'name': entry.field_str.tobytes().decode('utf-8'),
                'type': idawasm.common.struc_to_dict(ftype),
                'imported': True,
                # TODO: not sure if an import can be exported.
                'exported': False,
            }

            function_index += 1

        return functions

    def _parse_exported_functions(self):
        '''
        parse the export entries for functions.
        useful for recovering function names.

        Returns:
          Dict[int, Dict[str, any]]: from function index to dict with keys `index` and `name`.
        '''
        functions = {}
        export_section = self._get_section(wasm.wasmtypes.SEC_EXPORT)
        for entry in export_section.data.payload.entries:
            if entry.kind != idawasm.const.WASM_EXTERNAL_KIND_FUNCTION:
                continue

            functions[entry.index] = {
                'index': entry.index,
                'name': entry.field_str.tobytes().decode('utf-8'),
                'exported': True,
                # TODO: not sure if an export can be imported.
                'imported': False,
            }

        return functions

    def _parse_functions(self):
        imported_functions = self._parse_imported_functions()
        exported_functions = self._parse_exported_functions()

        functions = dict(imported_functions)

        function_section = self._get_section(wasm.wasmtypes.SEC_FUNCTION)
        code_section = self._get_section(wasm.wasmtypes.SEC_CODE)
        pcode_section = self._get_section_offset(wasm.wasmtypes.SEC_CODE)
        type_section = self._get_section(wasm.wasmtypes.SEC_TYPE)

        payload = code_section.data.payload
        ppayload = pcode_section + idawasm.common.offset_of(code_section.data, 'payload')
        pbody = ppayload + idawasm.common.offset_of(payload, 'bodies')
        for i in range(code_section.data.payload.count):
            function_index = len(imported_functions) + i
            body = code_section.data.payload.bodies[i]
            type_index = function_section.data.payload.types[i]
            ftype = type_section.data.payload.entries[type_index]

            local_types = []
            for locals_group in body.locals:
                ltype = locals_group.type
                for j in range(locals_group.count):
                    local_types.append(ltype)

            if function_index in exported_functions:
                name = exported_functions[function_index]['name']
                is_exported = True
            else:
                name = '$func%d' % (function_index)
                is_exported = False

            functions[function_index] = {
                'index': function_index,
                'name': name,
                'offset': pbody + idawasm.common.offset_of(body, 'code'),
                'type': idawasm.common.struc_to_dict(ftype),
                'exported': is_exported,
                'imported': False,
                'local_types': local_types,
                'size': idawasm.common.size_of(body, 'code'),
            }

            pbody += idawasm.common.size_of(body)

        return functions

    def _render_type(self, type_, name=None):
        if name is None:
            name = ''
        else:
            name = ' ' + name

        params = []
        if type_['param_count'] > 0:
            for i, param in enumerate(type_['param_types']):
                params.append(' (param $param%d %s)' % (i, idawasm.const.WASM_TYPE_NAMES[param]))
        sparam = ''.join(params)

        if type_['return_count'] == 0:
            sresult = ''
        elif type_['return_count'] == 1:
            sresult = ' (result %s)' % (idawasm.const.WASM_TYPE_NAMES[type_['return_type']])
        else:
            raise NotImplementedError('multiple return values')

        return '(func%s%s%s)' % (name, sparam, sresult)

    def _render_function_prototype(self, function):
        if function.get('imported'):
            name = '$import%d' % (function['index'])
            signature = self._render_type(function['type'], name=name)
            return '(import "%s" "%s" %s)' % (function['module'],
                                              function['name'],
                                              signature)
        else:
            return self._render_type(function['type'], name=function['name'])

    def load(self):
        '''
        load the state of the processor and analysis from the segments.

        the processor object may not be re-created, so we do our initializiation here.
        initialize the following fields:

          - self.buf
          - self.sections
          - self.functions
          - self.function_offsets
          - self.function_ranges
          - self.globals
          - self.branch_targets
        '''
        logger.info('parsing sections')
        buf = []
        for ea in idautils.Segments():
            # assume all the segments are contiguous, which is what our loader does
            buf.append(idc.GetManyBytes(idc.SegStart(ea), idc.SegEnd(ea) - idc.SegStart(ea)))

        self.buf = b''.join(buf)
        self.sections = list(wasm.decode.decode_module(self.buf))

        logger.info('parsing types')
        self.types = self._parse_types()

        logger.info('parsing globals')
        self.globals = self._parse_globals()

        logger.info('parsing functions')
        self.functions = self._parse_functions()

        # map from function offset to function object
        self.function_offsets = {f['offset']: f for f in self.functions.values() if 'offset' in f}

        # map from (function start, function end) to function object
        self.function_ranges = {
            (f['offset'], f['offset'] + f['size']): f
            for f in self.functions.values()
            if 'offset' in f
        }

        logger.info('computing branch targets')
        self.branch_targets = self._compute_branch_targets()

        self.deferred_noflows = {}
        self.deferred_flows = {}

        for function in self.functions.values():
            name = function['name'].encode('utf-8')
            if 'offset' in function:
                idc.MakeName(function['offset'], name)
                # notify_emu will be invoked from here.
                idc.MakeCode(function['offset'])
                idc.MakeFunction(function['offset'], function['offset'] + function['size'])

            if function.get('exported'):
                # TODO: this should really be done in the loader.
                # though, at the moment, we do a lot more analysis here in the processor.
                idc.add_entry(function['index'], function['offset'], name, True)

            # TODO: idc.add_entry for the start routine. need an example of this.

        for Analyzer in (idawasm.analysis.llvm.LLVMAnalyzer, ):
            logger.debug('running analyzer: %s', Analyzer.__name__)
            ana = Analyzer(self)
            ana.analyze()

    @ida_entry
    def notify_newfile(self, filename):
        '''
        handle file being analyzed for the first time.
        '''
        logger.info('new file: %s', filename)
        self.load()

    @ida_entry
    def notify_oldfile(self, filename):
        '''
        handle file loaded from existing .idb database.
        '''
        logger.info('existing database: %s', filename)
        self.load()

    @ida_entry
    def notify_savebase(self):
        '''
        the database is being saved.
        '''
        logger.info('saving wasm processor state.')

    @ida_entry
    def notify_endbinary(self, ok):
        """
         After loading a binary file
         args:
          ok - file loaded successfully?
        """
        logger.info('wasm module loaded.')

    @ida_entry
    def notify_get_autocmt(self, insn):
        '''
        fetch instruction auto-comment.

        Returns:
          Union[str, None]: the comment string, or None.
        '''
        if 'cmt' in self.instruc[insn.itype]:
            return self.instruc[insn.itype]['cmt']

    @ida_entry
    def notify_may_be_func(self, insn, state):
        '''
        can a function start at the given instruction?

        Returns:
          int: 100 if a function starts here, zero otherwise.
        '''
        if insn.ea in self.function_offsets:
            return 100
        else:
            return 0

    def notify_emu_BR_END(self, insn, next):
        # unconditional branch followed by END.

        # BR flows to the END
        idaapi.add_cref(insn.ea, insn.ea + insn.size, idaapi.fl_F)

        # unconditional branch, so END does not flow to following instruction
        self.deferred_noflows[next.ea] = True

        # branch target
        if insn.ea in self.branch_targets:
            targets = self.branch_targets[insn.ea]
            target_block = targets[insn.Op1.value]
            target_va = target_block['end_offset']
            self.deferred_flows[next.ea] = [(next.ea, target_va, idaapi.fl_JF)]

        return 1

    def notify_emu_BR_IF_END(self, insn, next):
        # BR_IF flows to the END
        idaapi.add_cref(insn.ea, insn.ea + insn.size, idaapi.fl_F)

        # conditional branch, so there will be a fallthrough flow.
        # the default behavior of `end` is to fallthrough, so don't change that.
        pass

        # branch target
        if insn.ea in self.branch_targets:
            targets = self.branch_targets[insn.ea]
            target_block = targets[insn.Op1.value]
            target_va = target_block['end_offset']
            self.deferred_flows[next.ea] = [(next.ea, target_va, idaapi.fl_JF)]

        return 1

    def notify_emu_RETURN_END(self, insn, next):
        # the RETURN will fallthrough to END,
        idaapi.add_cref(insn.ea, insn.ea + insn.size, idaapi.fl_F)

        # but the END will not fallthrough.
        self.deferred_noflows[next.ea] = True

        return 1

    def notify_emu_BR(self, insn):
        # handle an unconditional branch not at the end of a black.

        # unconditional branch does not fallthrough flow.
        pass

        # branch target
        if insn.ea in self.branch_targets:
            targets = self.branch_targets[insn.ea]
            target_block = targets[insn.Op1.value]
            target_va = target_block['end_offset']
            idaapi.add_cref(insn.ea, target_va, idaapi.fl_JF)

        return 1

    def notify_emu_BR_IF(self, insn):
        # handle a conditional branch not at the end of a block.
        # fallthrough flow
        idaapi.add_cref(insn.ea, insn.ea + insn.size, idaapi.fl_F)

        # branch target
        if insn.ea in self.branch_targets:
            targets = self.branch_targets[insn.ea]
            target_block = targets[insn.Op1.value]
            target_va = target_block['end_offset']
            idaapi.add_cref(insn.ea, target_va, idaapi.fl_JF)

        return 1

    def notify_emu_END(self, insn):
        for flow in self.deferred_flows.get(insn.ea, []):
            idaapi.add_cref(*flow)

        if insn.ea in self.branch_targets:
            targets = self.branch_targets[insn.ea]
            block = targets['block']
            if block['type'] == 'loop':
                # end of loop

                # noflow

                # branch back to top of loop
                target_va = block['offset']
                idaapi.add_cref(insn.ea, target_va, idaapi.fl_JF)

            elif block['type'] == 'if':
                # end of if
                raise NotImplementedError('if')

            elif block['type'] == 'block':
                # end of block
                # fallthrough flow, unless a deferred noflow from earlier, such as the case:
                #
                #     return
                #     end
                #
                # the RETURN is the end of the function, so no flow after the END.
                if insn.ea not in self.deferred_noflows:
                    idaapi.add_cref(insn.ea, insn.ea + insn.size, idaapi.fl_F)

            elif block['type'] == 'function':
                # end of function
                # noflow
                pass

            else:
                raise RuntimeError('unexpected block type: ' + block['type'])

        return 1

    @ida_entry
    def notify_emu(self, insn):
        '''
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        If zero is returned, the kernel will delete the instruction.

        adding xrefs is fairly straightforward, except for one hiccup:
        we'd like xrefs to flow from trailing END instructions,
         rather than getting orphaned in their own basic block.

        for example, consider the following:

            br $block0
            end

        if we place the code flow xref on the BR,
         then there is no flow to the END instruction,
         and the graph will look like:

            +------------+     +-----+
            |     ...    |     | end |
            | br $block0 |     +-----+
            +------------+
                   |
                  ...

        instead, we want the code flow xref to flow from the END,
         deferred from the BR, so the graph looks like this:

            +------------+
            |     ...    |
            | br $block0 |
            | end        |
            +------------+
                   |
                  ...

        to do this, at branching instruction,
         we detect if the following instruction is an END.
        if so, we flow through to the END,
         and queue the xrefs to be added when the END is processed.

        this assumes that the branching instructions are always analyzed before the END instructions.

        unfortunately, adding xrefs on subsequent instructions doesn't work (the node doesn't exist, or something).
        so, we have to used this "deferred" approach.
        '''

        # note: `next` may be None if invalid.
        next = idautils.DecodeInstruction(insn.ea + insn.size)

        # add drefs to globals
        for op in insn.ops:
            if not (op.type == idaapi.o_imm and op.specval == WASM_GLOBAL):
                continue

            global_va = self.globals[op.value]['offset']
            if insn.itype == self.itype_SET_GLOBAL:
                idc.add_dref(insn.ea, global_va, idc.dr_W)
            elif insn.itype == self.itype_GET_GLOBAL:
                idc.add_dref(insn.ea, global_va, idc.dr_R)
            else:
                raise RuntimeError('unexpected instruction referencing global: ' + str(insn))

        # TODO: add drefs to memory, but need example of this first.

        # handle cases like:
        #
        #     block
        #     ...
        #     br $foo
        #     end
        #
        # we want the cref to flow from the instruction `end`, not `br $foo`.
        if (insn.itype in {self.itype_BR,
                           self.itype_BR_IF,
                           self.itype_BR_TABLE}
              and next is not None                # NOQA: E127 continuation line over-indented for visual indent
              and next.itype == self.itype_END):  # NOQA: E127

            if insn.itype == self.itype_BR:
                return self.notify_emu_BR_END(insn, next)

            elif insn.itype == self.itype_BR_IF:
                return self.notify_emu_BR_IF_END(insn, next)

            elif insn.itype in (self.itype_BR_TABLE, ):
                raise NotImplementedError('br table')

        # handle cases like:
        #
        #     ...
        #     return
        #     end
        #
        # we want return to flow into the return, which should then not flow.
        elif (insn.itype == self.itype_RETURN
              and next is not None
              and next.itype == self.itype_END):
            return self.notify_emu_RETURN_END(insn, next)

        # handle other RETURN and UNREACHABLE instructions.
        # tbh, not sure how we'd encounter another RETURN, but we'll be safe.
        elif insn.get_canon_feature() & wasm.opcodes.INSN_NO_FLOW:
            return 1

        # handle an unconditional branch not at the end of a black.
        elif insn.itype == self.itype_BR:
            return self.notify_emu_BR(insn)

        elif insn.itype == self.itype_BR_TABLE:
            # haven't seen one of these yet, so don't know to handle exactly.
            raise NotImplementedError('br table')

        # handle a conditional branch not at the end of a block.
        elif insn.itype == self.itype_BR_IF:
            return self.notify_emu_BR_IF(insn)

        # add flows deferred from a prior branch, eg.
        #
        #     br $foo
        #     end
        #
        # flows deferred from the BR to the END insn.
        elif insn.itype == self.itype_END:
            return self.notify_emu_END(insn)

        # default behavior: fallthrough
        else:
            idaapi.add_cref(insn.ea, insn.ea + insn.size, idaapi.fl_F)

    @ida_entry
    def out_mnem(self, ctx):
        postfix = ''
        ctx.out_mnem(20, postfix)

    def _get_function(self, ea):
        '''
        fetch the function object that contains the given address.
        '''
        # warning: O(#funcs) scan here, called in a tight loop (render operand).
        for (start, end), f in self.function_ranges.items():
            if start <= ea < end:
                return f
        raise KeyError(ea)

    @ida_entry
    def notify_out_operand(self, ctx, op):
        '''
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        '''
        if op.type == WASM_BLOCK:
            if op.value == 0xFFFFFFC0:  # VarInt7 for 0x40
                # block has empty type
                pass
            else:
                # ref: https://webassembly.github.io/spec/core/binary/types.html#binary-valtype
                # TODO(wb): untested!
                ctx.out_keyword({
                    # TODO(wb): I don't think these constants will line up in practice
                    0x7F: 'type:i32',
                    0x7E: 'type:i64',
                    0x7D: 'type:f32',
                    0x7C: 'type:f64',
                }[op.value])
            return True

        elif op.type == idaapi.o_reg:
            wtype = op.specval
            if wtype == WASM_LOCAL:
                # output a function-local "register".
                # these are nice because they can be re-named by the analyst.
                #
                # eg.
                #     code:0D57    get_local    $param0
                #     code:0D4B    set_local    $local9
                #                                 ^
                #                                these things
                f = self._get_function(ctx.insn.ea)
                if op.reg < f['type']['param_count']:
                    # the first `param_count` indices reference a parameter,
                    ctx.out_register('$param%d' % (op.reg))
                else:
                    # and the remaining indices are local variables.
                    ctx.out_register('$local%d' % (op.reg))
                return True

        elif op.type == idaapi.o_imm:
            wtype = op.specval
            if wtype == WASM_GLOBAL:
                # output a reference to a global variable.
                # note that we provide the address of the variable,
                #  and IDA will insert the correct name.
                # this is particularly nice when a user re-names the variable.
                #
                # eg.
                #
                #     code:0D38    set_global   global_0
                #                                 ^
                #                                this thing
                g = self.globals[op.value]
                ctx.out_name_expr(op, g['offset'])
                return True

            elif wtype == WASM_FUNC_INDEX:
                f = self.functions[op.value]
                if 'offset' in f:
                    # output a reference to an existing function.
                    # note that we provide the address of the function,
                    #  and IDA will insert the correct name.
                    #
                    # eg.
                    #
                    #     code:0D9E    call   $func9
                    #                           ^
                    #                          this thing
                    ctx.out_name_expr(op, f['offset'])
                else:
                    # output a reference to a function by name,
                    # such as an imported routine.
                    # since this won't have a location in the binary,
                    #  we output the raw name of the function.
                    #
                    # TODO: link this to the import entry
                    ctx.out_keyword(f['name'].encode('utf-8'))
                return True

            elif wtype == WASM_TYPE_INDEX:
                # resolve the type index into a type,
                # then human-render it.
                #
                # eg.
                #
                #     code:0B7F  call_indirect  (func (param $param0 i32) (param $param1 i32) (result i32)), 0
                #                  ^
                #                 this thing
                type_index = op.value
                type = self.types[type_index]
                signature = self._render_type(type)

                ctx.out_keyword(signature)
                return True

            elif wtype == WASM_ALIGN:
                # output an alignment directive.
                #
                # eg.
                #
                #     code:0B54   i32.load    0x30, align:2
                #                                     ^
                #                                    this thing
                ctx.out_keyword('align:')
                width = self.dt_to_width(op.dtype)
                ctx.out_value(op, idaapi.OOFW_IMM | width)
                return True

            else:
                width = self.dt_to_width(op.dtype)
                ctx.out_value(op, idaapi.OOFW_IMM | width)
                return True

        # error case
        return False

    @ida_entry
    def notify_out_insn(self, ctx):
        '''
        must not change the database.

        args:
          ctx (object): has a `.insn` field.
        '''
        insn = ctx.insn
        ea = insn.ea

        # if this is the start of a function, render the function prototype.
        # like::
        #
        #     code:082E $func8:
        #     code:082E (func $func8 (param $param0 i32) (param $param1 i32) (result i32))
        if ea in self.function_offsets:
            # use idaapi.rename_regvar and idaapi.find_regvar to resolve $local/$param names
            # ref: https://reverseengineering.stackexchange.com/q/3038/17194
            fn = self.function_offsets[ea]
            proto = self._render_function_prototype(fn)
            ctx.gen_printf(0, proto + '\n')

        # the instruction has a mnemonic, then zero or more operands.
        # if more than one operand, the operands are separated by commas.
        #
        # eg.
        #
        #     code:0E30    i32.store    0x1C,  align:2
        #                      ^         ^  ^ ^     ^
        #                  mnemonic      |  | |     |
        #                             op[0] | |     |
        #                               comma |     |
        #                                     space |
        #                                        op[1]

        ctx.out_mnemonic()
        ctx.out_one_operand(0)

        for i in range(1, 3):
            op = insn[i]

            if op.type == idaapi.o_void:
                break

            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)

        # if this is a block instruction, annotate the relevant block.
        #
        # eg.
        #
        #     code:0E84     block        $block2
        #     code:0E86     loop         $loop3
        #     code:0F3F     end          $loop3
        #                                   ^
        #                                 this name

        # TODO: resolve block names on conditionals.
        # right now they look like:
        #
        #     code:0E77     br_if        1
        #
        # but we want something like this:
        #
        #     code:0E77     br_if        $block2

        # TODO: even better, we should use the location name, rather than auto-generated $block name
        # from this:
        #
        #     code:0E77     br_if        $block2
        #
        # want:
        #
        #     code:0E77     br_if        loc_error

        if insn.itype in (self.itype_BLOCK, self.itype_LOOP, self.itype_END) \
           and ea in self.branch_targets:

            targets = self.branch_targets[ea]
            block = targets['block']
            if block['type'] in ('block', 'loop'):
                ctx.out_tagon(idaapi.COLOR_UNAME)
                for c in ("$" + block['type'] + str(block['index'])):
                    ctx.out_char(c)
                ctx.out_tagoff(idaapi.COLOR_UNAME)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()

    @ida_entry
    def notify_ana(self, insn):
        '''
        decodes an instruction and place it into the given insn.

        Args:
          insn (idaapi.insn_t): the instruction to populate.

        Returns:
          int: size of insn on success, 0 on failure.
        '''

        # as of today (v1), each opcode is a single byte
        opb = insn.get_next_byte()

        if opb not in wasm.opcodes.OPCODE_MAP:
            return 0

        # translate from opcode index to IDA-specific const.
        # as you can see elsewhere, IDA insn consts have to be contiguous,
        #  so we can't just re-use the opcode index.
        insn.itype = self.insns[opb]['id']

        # fetch entire instruction buffer to decode
        if wasm.opcodes.OPCODE_MAP.get(opb).imm_struct:
            # opcode has operands that we must decode

            # warning: py2.7-specific
            # can't usually just cast the bytearray to a string without explicit decode.
            # assumption: instruction will be less than 0x10 bytes.
            buf = str(bytearray(idc.GetManyBytes(insn.ea, 0x10)))
        else:
            # single byte instruction

            # warning: py2.7-specific
            buf = str(bytearray([opb]))

        bc = next(wasm.decode.decode_bytecode(buf))
        for _ in range(1, bc.len):
            # consume any additional bytes.
            # this is how IDA knows the size of the insn.
            insn.get_next_byte()

        insn.Op1.type = idaapi.o_void
        insn.Op2.type = idaapi.o_void

        # decode instruction operand.
        # as of today (V1), there's at most a single operand.
        # (though there may also be alignment directive, etc. that we place into Op2+)
        #
        # place the operand value into `.value`, unless its a local, and then use `.reg`.
        # use `.specval` to indicate special handling of register, possible cases:
        #   WASM_LOCAL
        #   WASM_GLOBAL
        #   WASM_FUNC_INDEX
        #   WASM_TYPE_INDEX
        #   WASM_BLOCK
        #   WASM_ALIGN
        #
        if bc.imm is not None:
            immtype = bc.imm.get_meta().structure

            SHOW_FLAGS = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW

            # wasm is currently single-byte opcode only
            # therefore the first operand must be found at offset 0x1.
            insn.Op1.offb = 1
            insn.Op1.offo = 1

            # by default, display the operand, unless overridden below.
            insn.Op1.flags = SHOW_FLAGS

            if immtype == wasm.immtypes.BlockImm:
                # sig = BlockTypeField()
                insn.Op1.type = WASM_BLOCK
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.sig
                insn.Op1.specval = WASM_BLOCK

            elif immtype == wasm.immtypes.BranchImm:
                # relative_depth = VarUInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.relative_depth

            elif immtype == wasm.immtypes.BranchTableImm:
                # target_count = VarUInt32Field()
                # target_table = RepeatField(VarUInt32Field(), lambda x: x.target_count)
                # default_target = VarUInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.target_count

                insn.Op2.type = idaapi.o_imm
                insn.Op2.offb = 1  # TODO(wb): fixup offset of Op2
                insn.Op2.offo = 1  # TODO(wb): fixup offset of Op2
                insn.Op2.flags = SHOW_FLAGS
                insn.Op2.dtype = idaapi.dt_dword
                insn.Op2.value = bc.imm.target_table

                insn.Op3.type = idaapi.o_imm
                insn.Op3.offb = 1  # TODO(wb): fixup offset of Op3
                insn.Op3.offo = 1  # TODO(wb): fixup offset of Op3
                insn.Op3.flags = SHOW_FLAGS
                insn.Op3.dtype = idaapi.dt_dword
                insn.Op3.value = bc.imm.default_target

            elif immtype == wasm.immtypes.CallImm:
                # function_index = VarUInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.function_index
                insn.Op1.specval = WASM_FUNC_INDEX

            elif immtype == wasm.immtypes.CallIndirectImm:
                # type_index = VarUInt32Field()
                # reserved = VarUInt1Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.type_index
                insn.Op1.specval = WASM_TYPE_INDEX

                insn.Op2.type = idaapi.o_imm
                insn.Op2.offb = 1  # TODO(wb): fixup offset of Op2
                insn.Op2.offo = 1  # TODO(wb): fixup offset of Op2
                insn.Op2.flags = SHOW_FLAGS
                insn.Op2.dtype = idaapi.dt_dword
                insn.Op2.value = bc.imm.reserved

            elif immtype == wasm.immtypes.LocalVarXsImm:
                # local_index = VarUInt32Field()
                insn.Op1.type = idaapi.o_reg
                insn.Op1.reg = bc.imm.local_index
                insn.Op1.specval = WASM_LOCAL

            elif immtype == wasm.immtypes.GlobalVarXsImm:
                # global_index = VarUInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.global_index
                insn.Op1.specval = WASM_GLOBAL

            elif immtype == wasm.immtypes.MemoryImm:
                # flags = VarUInt32Field()
                # offset = VarUInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.offset

                insn.Op2.type = idaapi.o_imm
                insn.Op2.offb = 1  # TODO(wb): fixup offset of Op2
                insn.Op2.offo = 1  # TODO(wb): fixup offset of Op2
                insn.Op2.flags = SHOW_FLAGS
                insn.Op2.dtype = idaapi.dt_dword
                insn.Op2.value = bc.imm.flags
                insn.Op2.specval = WASM_ALIGN

            elif immtype == wasm.immtypes.CurGrowMemImm:
                # reserved = VarUInt1Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.reserved

            elif immtype == wasm.immtypes.I32ConstImm:
                # value = VarInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.value

            elif immtype == wasm.immtypes.I64ConstImm:
                # value = VarInt64Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.dtype = idaapi.dt_qword
                insn.Op1.value = bc.imm.value

            elif immtype == wasm.immtypes.F32ConstImm:
                # value = UInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.dtype = idaapi.dt_float
                insn.Op1.value = bc.imm.value

            elif immtype == wasm.immtypes.F64ConstImm:
                # value = UInt64Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.dtype = idaapi.dt_double
                insn.Op1.value = bc.imm.value

        return insn.size

    def init_instructions(self):
        # Now create an instruction table compatible with IDA processor module requirements
        self.insns = {}
        for i, op in enumerate(wasm.opcodes.OPCODES):
            self.insns[op.id] = {
                # the opcode byte
                'opcode': op.id,
                # the IDA constant for this instruction
                'id': i,
                # danger: this must be an ASCII-encoded byte string, *not* unicode!
                'name': op.mnemonic.encode('ascii'),
                'feature': op.flags,
                'cmt': idawasm.const.WASM_OPCODE_DESCRIPTIONS.get(op.id),
            }
            clean_mnem = op.mnemonic.encode('ascii').replace('.', '_').replace('/', '_').upper()
            # the itype constant value must be contiguous, which sucks, because its not the op.id value.
            setattr(self, 'itype_' + clean_mnem, i)

        # Array of instructions
        # the index into this array apparently must match the `self.itype_*`.
        self.instruc = list(sorted(self.insns.values(), key=lambda i: i['id']))

        self.instruc_start = 0
        self.instruc_end = len(self.instruc)
        self.icode_return = self.itype_RETURN

    def init_registers(self):
        """This function parses the register table and creates corresponding ireg_XXX constants"""

        # Registers definition
        # for wasm, "registers" are local variables.
        self.reg_names = []

        # we'd want to scan the module and pick the max number of parameters,
        # however, the data isn't available yet,
        # so we pick a scary large number.
        #
        # note: IDA reg_t size is 16-bits
        MAX_LOCALS = 0x1000
        for i in range(MAX_LOCALS):
            self.reg_names.append("$local%d" % (i))

        # we'd want to scan the module and pick the max number of parameters,
        # however, the data isn't available yet,
        # so we pick a scary large number.
        MAX_PARAMS = 0x1000
        for i in range(MAX_PARAMS):
            self.reg_names.append("$param%d" % (i))

        # these are fake, "virtual" registers.
        # req'd for IDA, apparently.
        # (not actually used in wasm)
        self.reg_names.append("SP")
        self.reg_names.append("CS")
        self.reg_names.append("DS")

        # Create the ireg_XXXX constants.
        # for wasm, will look like: ireg_LOCAL0, ireg_PARAM0
        for i in range(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i].replace('$', ''), i)

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        # (not actually used in wasm)
        self.reg_first_sreg = self.ireg_CS
        self.reg_last_sreg = self.ireg_DS

        # number of CS register
        # (not actually used in wasm)
        self.reg_code_sreg = self.ireg_CS

        # number of DS register
        # (not actually used in wasm)
        self.reg_data_sreg = self.ireg_DS

    def __init__(self):
        # this is called prior to loading a binary, so don't read from the database here.
        idaapi.processor_t.__init__(self)
        self.PTRSZ = 4  # Assume PTRSZ = 4 by default
        self.init_instructions()
        self.init_registers()

        # these will be populated by `notify_newfile`
        self.buf = b''
        # ordered list of wasm section objects
        self.sections = []
        # map from function index to function object
        self.functions = {}
        # map from virtual address to function object
        self.function_offsets = {}
        # map from (va-start, va-end) to function object
        self.function_ranges = {}
        # map from global index to global object
        self.globals = {}
        # map from va to map from relative depth to va
        self.branch_targets = {}
        # list of type descriptors
        self.types = []

        # map from address to list of cref arguments.
        # used by `notify_emu`.
        self.deferred_flows = {}

        # set of addresses which should not flow.
        # map from address to True.
        # used by `notify_emu`.
        self.deferred_noflows = {}


def PROCESSOR_ENTRY():
    logging.basicConfig(level=logging.DEBUG)
    return wasm_processor_t()
