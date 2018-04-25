# TODO:
#  - parse items up front
#    - all sections
#    - blocks and branch targets
#  - use $paramN for params, based on function prototype
#  - mark branch code xrefs during emu
#  - add names for globals
#  - mark data xref to memory load/store
#  - mark data xref to global load/store
#  - create functions
#  - enable global var renaming
#  - show function prototype and local var layout at function start
#    - leading parenthesis
#    - fn name
#    - arguments and types
#    - local vars and types
#  - render trailing parenthesis
#  - compute stack deltas
#  - add exports for exports, start function

'''

# WebAssembly processor module design

## types

wasm supports memory, discrete global variables, parameters, local variables, and a stack.
there are no registers.
how do we map these into IDA concepts that we can rename and reason about?

parameters and local variables - map to "registers".
you can rename registers with function scope, see: https://www.hex-rays.com/products/ida/support/idadoc/1346.shtml

stack: since operands can only affect elements at the top (no arbitrary indexing), we'll simply track the sp for fun.

memory: use offsets into memory section.

global variables: use offsets into globals section.
'''

import sys
import struct
import logging
import functools

import wasm
import wasm.decode
import wasm.wasmtypes
import hexdump

import idc
import idaapi
import idautils

import idawasm.const
from idawasm.common import *


logger = logging.getLogger(__name__)

PLFM_WASM = 0x8069

# these are wasm-specific operand types
WASM_LOCAL = idaapi.o_idpspec0
WASM_GLOBAL = idaapi.o_idpspec1
WASM_FUNC_INDEX = idaapi.o_idpspec2
WASM_TYPE_INDEX = idaapi.o_idpspec3
WASM_BLOCK = idaapi.o_idpspec4
WASM_ALIGN = idaapi.o_idpspec5

def no_exceptions(f):
    '''
    decorator that catches and logs any exceptoins.
    the exceptions are swallowed, and `0` is returned.
    '''
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except:
            logger.error('exception in %s', f.__name__, exc_info=True)
            return 0
    return wrapper


# tags functions that are invoked from IDA-land.
ida_entry = no_exceptions


class wasm_processor_t(idaapi.processor_t):
    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = PLFM_WASM

    # Processor features
    flag = idaapi.PR_USE32 | idaapi.PR_RNAMESOK | idaapi.PRN_HEX | idaapi.PR_NO_SEGMOVE

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['wasm']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['WebAssembly']

    # size of a segment register in bytes
    segreg_size = 0

    # Array of typical code start sequences (optional)
    # codestart = ['\x60\x00']  # 60 00 xx xx: MOVqw         SP, SP-delta

    # Array of 'return' instruction opcodes (optional)
    # retcodes = ['\x04\x00']   # 04 00: RET

    # You should define 2 virtual segment registers for CS and DS.
    # Let's call them rVcs and rVds.

    # icode of the first instruction
    instruc_start = 0

    #
    #      Size of long double (tbyte) for this processor
    #      (meaningful only if ash.a_tbyte != NULL)
    #
    tbyte_size = 0

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : idaapi.ASH_HEXF3 | idaapi.AS_UNEQU | idaapi.AS_COLON | idaapi.ASB_BINF4 | idaapi.AS_N2CHR,

        # user defined flags (local only for IDP)
        # you may define and use your own bits
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "WebAssembly assembler",

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";;",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        'a_qword': "dq",

        # remove if not allowed
        'a_oword': "xmmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        'a_tbyte': "dt",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string)
        'a_sizeof_fmt': "size %s",
    } # Assembler


    def dt_to_width(self, dt):
        """Returns OOFW_xxx flag given a dt_xxx"""
        if   dt == idaapi.dt_byte:  return idaapi.OOFW_8
        elif dt == idaapi.dt_word:  return idaapi.OOFW_16
        elif dt == idaapi.dt_dword: return idaapi.OOFW_32
        elif dt == idaapi.dt_qword: return idaapi.OOFW_64

    # ----------------------------------------------------------------------
    # Processor module callbacks
    #
    # ----------------------------------------------------------------------
    @ida_entry
    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        if 'cmt' in self.instruc[insn.itype]:
          return self.instruc[insn.itype]['cmt'](insn)

    @ida_entry
    def notify_may_be_func(self, insn, state):
        """
        can a function start here?
        the instruction is in 'insn'
          arg: state -- autoanalysis phase
            state == 0: creating functions
                  == 1: creating chunks
          returns: probability 0..100
        """
        logger.debug('notify may be func')
        # TODO(wb): parse functions section for function start addresses. nothing else.

        if is_reg(insn.Op1, self.ireg_SP) and insn.Op2.type == o_displ and\
            insn.Op2.phrase == self.ireg_SP and (insn.Op2.specval & self.FLo_INDIRECT) == 0:
            # mov SP, SP+delta
            if SIGNEXT(insn.Op2.addr, self.PTRSZ*8) < 0:
                return 100
            else:
                return 0
        return 10

    def add_stkpnt(self, insn, pfn, v):
        logger.debug('add stkpnt')
        if pfn:
            end = insn.ea + insn.size
            if not is_fixed_spd(end):
                ida_frame.add_auto_stkpnt(pfn, end, v)

    def trace_sp(self, insn):
        """
        Trace the value of the SP and create an SP change point if the current
        instruction modifies the SP.
        """
        logger.debug('trace sp')
        pfn = get_func(insn.ea)
        if not pfn:
            return
        if is_reg(insn.Op1, self.ireg_SP) and insn.itype in [self.itype_MOVbw, self.itype_MOVww,
                                            self.itype_MOVdw, self.itype_MOVqw, self.itype_MOVbd,
                                            self.itype_MOVwd, self.itype_MOVdd, self.itype_MOVqd,
                                            self.itype_MOVsnw, self.itype_MOVsnd, self.itype_MOVqq]:
            # MOVqw         SP, SP-0x30
            # MOVqw         SP, SP+0x30
            if insn.Op2.type == o_displ and insn.Op2.phrase == self.ireg_SP and (insn.Op2.specval & self.FLo_INDIRECT) == 0:
                spofs = SIGNEXT(insn.Op2.addr, self.PTRSZ*8)
                self.add_stkpnt(insn, pfn, spofs)
        elif insn.itype in [self.itype_PUSH, self.itype_PUSHn]:
            spofs = dt_to_bits(insn.Op1.dtype) // 8
            self.add_stkpnt(insn, pfn, -spofs)
        elif insn.itype in [self.itype_POP, self.itype_POPn]:
            spofs = dt_to_bits(insn.Op1.dtype) // 8
            self.add_stkpnt(insn, pfn, spofs)

    @ida_entry
    def notify_emu(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        # add fall-through flows
        if insn.get_canon_feature() & wasm.opcodes.INSN_NO_FLOW:
            # itype_UNREACHABLE, itype_RETURN
            # noflow
            pass
        elif insn.itype in (self.itype_BR, self.itype_BR_TABLE):
            # noflow
            pass
        else:
            idaapi.add_cref(insn.ea, insn.ea + insn.size, idaapi.fl_F)

        return 1

        aux = self.get_auxpref(insn)
        Feature = insn.get_canon_feature()

        if Feature & CF_JUMP:
            remember_problem(PR_JUMP, insn.ea)

        # is it an unconditional jump?
        uncond_jmp = insn.itype in [self.itype_JMP8, self.itype_JMP] and (aux & (self.FLa_NCS|self.FLa_CS)) == 0

        # add flow
        flow = (Feature & CF_STOP == 0) and not uncond_jmp
        if flow:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        # trace the stack pointer if:
        #   - it is the second analysis pass
        #   - the stack pointer tracing is allowed
        if may_trace_sp():
            if flow:
                self.trace_sp(insn) # trace modification of SP register
            else:
                recalc_spd(insn.ea) # recalculate SP register for the next insn

        return 1

    @ida_entry
    def out_mnem(self, ctx):
        postfix = ''
        ctx.out_mnem(20, postfix)

    @ida_entry
    def notify_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        if op.type == WASM_BLOCK:
            if op.value == 0xFFFFFFC0:  # VarInt7 for 0x40
                ctx.out_keyword('type:empty')
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
                sreg = self.reg_names[op.reg]
                ctx.out_register(sreg)
                return True

        elif op.type == idaapi.o_imm:
            wtype = op.specval
            if wtype == WASM_GLOBAL:
                # TODO: would like to make this a name that a user can re-name.
                # might have to make this some kind of address.
                ctx.out_keyword('$global%d' % (op.value))
                return True

            elif wtype == WASM_LOCAL:
                # TODO: would like to make this a name that a user can re-name.
                ctx.out_keyword('$var%d' % (op.value))
                return True

            elif wtype == WASM_FUNC_INDEX:
                ctx.out_keyword('func:')
            elif wtype == WASM_TYPE_INDEX:
                ctx.out_keyword('type:')

            elif wtype == WASM_ALIGN:
                return False

            width = self.dt_to_width(op.dtype)
            ctx.out_value(op, idaapi.OOFW_IMM | width)
            return True

        else:
            return False

        return True

    @ida_entry
    def notify_out_insn(self, ctx):
        '''
        must not change the database.

        args:
          ctx (object): has a `.insn` field.
        '''
        ctx.out_mnemonic()
        ctx.out_one_operand(0)

        for i in xrange(1, 3):
            op = ctx.insn[i]

            if op.type == idaapi.o_void:
                break

            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()

    @ida_entry
    def notify_ana(self, insn):
        """
        Decodes an instruction into insn
        """
        opb = insn.get_next_byte()

        if opb not in wasm.opcodes.OPCODE_MAP:
            return 0

        insn.itype = self.insns[opb]['id']

        if wasm.opcodes.OPCODE_MAP.get(opb).imm_struct:
            # warning: py2.7
            buf = str(bytearray(idc.GetManyBytes(insn.ea, 0x10)))
        else:
            # warning: py2.7
            buf = str(bytearray([opb]))

        bc = next(wasm.decode.decode_bytecode(buf))
        for _ in range(1, bc.len):
            # consume any additional bytes
            insn.get_next_byte()

        insn.Op1.type  = idaapi.o_void
        insn.Op2.type  = idaapi.o_void

        if bc.imm is not None:
            immtype = bc.imm.get_meta().structure
            if immtype == wasm.immtypes.BlockImm:
                # sig = BlockTypeField()
                insn.Op1.type = WASM_BLOCK
                # wasm is currently single-byte opcode only
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.sig
                insn.Op1.specval = WASM_BLOCK

            elif immtype == wasm.immtypes.BranchImm:
                # relative_depth = VarUInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.relative_depth

            elif immtype == wasm.immtypes.BranchTableImm:
                # target_count = VarUInt32Field()
                # target_table = RepeatField(VarUInt32Field(), lambda x: x.target_count)
                # default_target = VarUInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.target_count

                insn.Op2.type = idaapi.o_imm
                insn.Op2.offb = 1  # TODO(wb)
                insn.Op2.offo = 1  # TODO(wb)
                insn.Op2.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op2.dtype = idaapi.dt_dword
                insn.Op2.value = bc.imm.target_table

                insn.Op3.type = idaapi.o_imm
                insn.Op3.offb = 1  # TODO(wb)
                insn.Op3.offo = 1  # TODO(wb)
                insn.Op3.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op3.dtype = idaapi.dt_dword
                insn.Op3.value = bc.imm.default_target

            elif immtype == wasm.immtypes.CallImm:
                # function_index = VarUInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.function_index
                insn.Op1.specval = WASM_FUNC_INDEX

            elif immtype == wasm.immtypes.CallIndirectImm:
                # type_index = VarUInt32Field()
                # reserved = VarUInt1Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.type_index
                insn.Op1.specval = WASM_TYPE_INDEX

                insn.Op2.type = idaapi.o_imm
                insn.Op2.offb = 1  # TODO(wb)
                insn.Op2.offo = 1  # TODO(wb)
                insn.Op2.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op2.dtype = idaapi.dt_dword
                insn.Op2.value = bc.imm.reserved

            elif immtype == wasm.immtypes.LocalVarXsImm:
                # local_index = VarUInt32Field()
                insn.Op1.type = idaapi.o_reg
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                #insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                #insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.reg  = bc.imm.local_index
                insn.Op1.specval = WASM_LOCAL

            elif immtype == wasm.immtypes.GlobalVarXsImm:
                # global_index = VarUInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.global_index
                insn.Op1.specval = WASM_GLOBAL

            elif immtype == wasm.immtypes.MemoryImm:
                # flags = VarUInt32Field()
                # offset = VarUInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.offb = 1  # TODO(wb)
                insn.Op1.offo = 1  # TODO(wb)
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.offset

                insn.Op2.type = idaapi.o_imm
                insn.Op2.offb = 1
                insn.Op2.offo = 1
                insn.Op2.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op2.dtype = idaapi.dt_dword
                insn.Op2.value = bc.imm.flags
                insn.Op2.specval = WASM_ALIGN

            elif immtype == wasm.immtypes.CurGrowMemImm:
                # reserved = VarUInt1Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.reserved

            elif immtype == wasm.immtypes.I32ConstImm:
                # value = VarInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.value = bc.imm.value

            elif immtype == wasm.immtypes.I64ConstImm:
                # value = VarInt64Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op1.dtype = idaapi.dt_qword
                insn.Op1.value = bc.imm.value

            elif immtype == wasm.immtypes.F32ConstImm:
                # value = UInt32Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op1.dtype = idaapi.dt_float
                insn.Op1.value = bc.imm.value

            elif immtype == wasm.immtypes.F64ConstImm:
                # value = UInt64Field()
                insn.Op1.type = idaapi.o_imm
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
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
                'cmd': None,          # TODO(wb): add cmt help
            }
            clean_mnem = op.mnemonic.encode('ascii').replace('.', '_').replace('/', '_').upper()
            # the itype constant value must be contiguous, which sucks, because its not the op.id value.
            setattr(self, 'itype_' + clean_mnem, i)

        # Array of instructions
        # the index into this array apparently must match the `self.itype_*`.
        self.instruc = list(sorted(self.insns.values(), key=lambda i: i['id']))
        self.instruc_end = len(self.instruc)

        # Icode of return instruction. It is ok to give any of possible return
        # instructions
        self.icode_return = self.itype_RETURN

    def init_registers(self):
        """This function parses the register table and creates corresponding ireg_XXX constants"""

        # Registers definition
        # for wasm, "registers" are local variables.
        self.reg_names = []

        # note: IDA reg_t size is 16-bits
        # TODO: scan functions and pick max local size.
        MAX_LOCALS = 0x100
        for i in range(MAX_LOCALS):
            self.reg_names.append("$local%d" % (i))
        # TODO: scan functions and pick max param size.
        MAX_PARAMS = 0x100
        for i in range(MAX_PARAMS):
            self.reg_names.append("$param%d" % (i))

        # these are fake, "virtual" registers.
        # req'd for IDA, apparently.
        self.reg_names.append("SP")
        self.reg_names.append("CS")
        self.reg_names.append("DS")

        # Create the ireg_XXXX constants.
        # for wasm, will look like: ireg_LOCAL0, ireg_PARAM0
        for i in xrange(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i].replace('$', ''), i)

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.ireg_CS
        self.reg_last_sreg  = self.ireg_DS

        # number of CS register
        self.reg_code_sreg = self.ireg_CS

        # number of DS register
        self.reg_data_sreg = self.ireg_DS

    def _get_section(self, section_id):
        for i, section in enumerate(self.sections):
            if i == 0:
                continue

            if section.data.id != section_id:
                continue

            return section

        raise KeyError(section_id)

    def _get_section_offset(self, section_id):
        p = 0
        for i, section in enumerate(self.sections):
            if i == 0:
                p += size_of(section.data)
                continue

            if section.data.id != section_id:
                p += size_of(section.data)
                continue

            return p

        raise KeyError(section_id)

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
                'type': struc_to_dict(ftype),
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

        pbody = pcode_section + offset_of(code_section.data, 'payload') + offset_of(code_section.data.payload, 'bodies')
        for i in range(code_section.data.payload.count):
            function_index = len(imported_functions) + i
            body = code_section.data.payload.bodies[i]
            type_index = function_section.data.payload.types[i]
            ftype = type_section.data.payload.entries[type_index]

            functions[function_index] = {
                'index': function_index,
                'offset': pbody,
                'type': struc_to_dict(ftype),
                'exported': False,
                'imported': False,
            }

            if function_index in exported_functions:
                functions[function_index]['name'] = exported_functions[function_index]['name']
                functions[function_index]['exported'] = True

            pbody += size_of(body)

        return functions

    def notify_newfile(self, filename):
        logger.info('new file: %s', filename)

        buf = []
        for ea in idautils.Segments():
            # assume all the segments are contiguous, which is what our loader does
            buf.append(idc.GetManyBytes(idc.SegStart(ea), idc.SegEnd(ea) - idc.SegStart(ea)))

        self.buf = b''.join(buf)
        self.sections = list(wasm.decode.decode_module(self.buf))
        self.functions = self._parse_functions()
        from pprint import pprint
        pprint(self.functions)

    def __init__(self):
        # this is called prior to loading a binary, so don't read from the database here.
        idaapi.processor_t.__init__(self)
        self.PTRSZ = 4 # Assume PTRSZ = 4 by default
        self.init_instructions()
        self.init_registers()

        # these will be populated by `notify_newfile`
        self.buf = b''
        self.sections = []
        self.functions = {}


def PROCESSOR_ENTRY():
    logging.basicConfig(level=logging.DEBUG)
    return wasm_processor_t()
