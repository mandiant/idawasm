import sys
import struct
import logging
import functools

import wasm
import wasm.decode
import wasm.wasmtypes

import idc
import idaapi


logger = logging.getLogger(__name__)

PLFM_WASM = 0x8069

# these are wasm-specific operand types
WASM_LOCAL = idaapi.o_idpspec0
WASM_GLOBAL = idaapi.o_idpspec1
WASM_GROW_MEM = idaapi.o_idpspec2
WASM_INDIRECT = idaapi.o_idpspec3
WASM_BLOCK = idaapi.o_idpspec4
WASM_UNK = idaapi.o_idpspec5


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
    flag = idaapi.PR_SEGS | idaapi.PR_DEFSEG32 | idaapi.PR_USE32 | idaapi.PRN_HEX | idaapi.PR_RNAMESOK | idaapi.PR_NO_SEGMOVE

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
        'cmnt': ";",

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

    # ----------------------------------------------------------------------
    # Some internal flags used by the decoder, emulator and output
    # operand size or move size; can be in both auxpref and OpN.specval
    FL_B               = 0x0001 # 8 bits
    FL_W               = 0x0002 # 16 bits
    FL_D               = 0x0004 # 32 bits
    FL_Q               = 0x0008 # 64 bits

    def native_dt(self):
        return dt_qword if self.PTRSZ==8 else dt_dword

    # ----------------------------------------------------------------------
    # Processor module callbacks
    #
    # ----------------------------------------------------------------------
    @ida_entry
    def notify_get_frame_retsize(self, func_ea):
        """
        Get size of function return address in bytes
        for EBC it's 8 bytes of the actual return address
        plus 8 bytes of the saved frame address
        """
        logger.debug('notify get frame retsize')
        return 16

    @ida_entry
    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        logger.debug('notify get autocmt')
        if 'cmt' in self.instruc[insn.itype]:
          return self.instruc[insn.itype]['cmt'](insn)

    @ida_entry
    def notify_can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: bool
        """
        return True

    @ida_entry
    def notify_is_align_insn(self, ea):
        """
        Is the instruction created only for alignment purposes?
        Returns: If so, the number of bytes in the instruction
        """
        return 0

    @ida_entry
    def notify_newfile(self, filename):
        logger.debug('notify newfile: %s', filename)

    @ida_entry
    def notify_oldfile(self, filename):
        logger.debug('notify oldfile: %s', filename)

    @ida_entry
    def notify_out_header(self, ctx):
        """function to produce start of disassembled text"""
        logger.debug('notify out header')
        ctx.out_line("; natural unit size: %d bits" % (self.PTRSZ*8))
        ctx.flush_outbuf(0)

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

    def check_thunk(self, addr):
        """
        Check for EBC thunk at addr
        dd fnaddr - (addr+4), 0, 0, 0
        """
        logger.debug("check thunk")
        delta = get_dword(addr)
        fnaddr = (delta + addr + 4) & 0xFFFFFFFF
        if is_off(get_flags(addr), 0):
            # already an offset
            if ida_offset.get_offbase(addr, 0) == addr + 4:
                return fnaddr
            else:
                return None
        # should be followed by three zeroes
        if delta == 0 or get_dword(addr+4) != 0 or\
        get_dword(addr+8) != 0 or get_dword(addr+12) != 0:
            return None
        if segtype(fnaddr) == SEG_CODE:
            # looks good, create the offset
            create_dword(addr)
            if ida_offset.op_offset(addr, 0, REF_OFF32|REFINFO_NOBASE, BADADDR, addr + 4):
                return fnaddr
            else:
                return None

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
        logger.debug('notify emu')

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
    def notify_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        print('notify out operand')
        optype = op.type
        fl     = op.specval
        signed = OOF_SIGNED if fl & self.FLo_SIGNED != 0 else 0
        def_arg = is_defarg(get_flags(ctx.insn.ea), op.n)

        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])

        elif optype == o_imm:
            # for immediate loads, use the transfer width (type of first operand)
            if op.n == 1:
                width = self.dt_to_width(ctx.insn.Op1.dtype)
            else:
                width = OOFW_32 if self.PTRSZ == 4 else OOFW_64
            ctx.out_value(op, OOFW_IMM | signed | width)

        elif optype in [o_near, o_mem]:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)

        elif optype == o_displ:
            indirect = fl & self.FLo_INDIRECT != 0
            if indirect:
                ctx.out_symbol('[')

            ctx.out_register(self.reg_names[op.reg])

            if op.addr != 0 or def_arg:
                ctx.out_value(op, OOF_ADDR | (OOFW_32 if self.PTRSZ == 4 else OOFW_64) | signed | OOFS_NEEDSIGN)

            if indirect:
                ctx.out_symbol(']')
        else:
            return False

        return True

    @ida_entry
    def out_mnem(self, ctx):
        postfix = ''
        ctx.out_mnem(20, postfix)

    @ida_entry
    def notify_out_insn(self, ctx):
        '''
        must not change the database.

        args:
          ctx (object): has a `.insn` field.
        '''
        ctx.out_mnemonic()
        #ctx.out_one_operand(0)
        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return
        # TODO(wb): need to output the operand

        ctx.out_one_operand(0)

        for i in xrange(1, 3):
            op = ctx.insn[i]

            if op.type == o_void:
                break

            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)

        if ctx.insn.itype == self.itype_MOVREL:
            fnaddr = self.check_thunk(ctx.insn.Op2.addr)
            if fnaddr != None:
                nm = get_ea_name(fnaddr, ida_name.GN_VISIBLE)
                if nm:
                    ctx.out_line("; Thunk to " + nm, COLOR_AUTOCMT)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()

    @ida_entry
    def notify_ana(self, insn):
        """
        Decodes an instruction into insn
        """
        logger.debug('decode instruction at 0x%X', insn.ea)
        opb = insn.get_next_byte()

        if opb not in wasm.opcodes.OPCODE_MAP:
            return 0

        op = wasm.opcodes.OPCODE_MAP.get(opb)
        insn.itype = op.id

        if op.imm_struct:
            buf = idc.GetManyBytes(insn.ea, 0x10)
        else:
            buf = bytes([opb])

        bc = next(wasm.decode.decode_bytecode(buf))
        for _ in range(1, bc.len):
            # consume any additional bytes
            insn.get_next_byte()

        logging.debug('bytecode: %s', bc)

        insn.Op1.type  = idaapi.o_void
        insn.Op2.type  = idaapi.o_void

        if bc.imm is not None:
            logging.debug('immediate: %s', bc.imm.get_meta().structure)
            for field in bc.imm.get_meta().fields:
                logging.debug('  - %s: %s', field.name, str(getattr(bc.imm, field.name)))

            immtype = bc.imm.get_meta().structure
            logger.info('immtype: %s', immtype)
            logger.info('%s', immtype == wasm.immtypes.GlobalVarXsImm)
            if immtype == wasm.immtypes.BlockImm:
                # sig = BlockTypeField()
                '''
                insn.Op1.type = WASM_BLOCK
                # wasm is currently single-byte opcode only
                insn.Op1.offb = 1
                insn.Op1.offo = 1
                insn.Op1.flags = idaapi.OF_NO_BASE_DISP | idaapi.OF_NUMBER | idaapi.OF_SHOW
                insn.Op1.dtype = idaapi.dt_dword
                insn.Op1.specval = bc.imm.sig
                '''

            elif immtype == wasm.immtypes.BranchImm:
                # relative_depth = VarUInt32Field()
                pass

            elif immtype == wasm.immtypes.BranchTableImm:
                # target_count = VarUInt32Field()
                # target_table = RepeatField(VarUInt32Field(), lambda x: x.target_count)
                # default_target = VarUInt32Field()
                pass

            elif immtype == wasm.immtypes.CallImm:
                # function_index = VarUInt32Field()
                pass

            elif immtype == wasm.immtypes.CallIndirectImm:
                # type_index = VarUInt32Field()
                # reserved = VarUInt1Field()
                pass

            elif immtype == wasm.immtypes.LocalVarXsImm:
                # local_index = VarUInt32Field()
                pass

            elif immtype == wasm.immtypes.GlobalVarXsImm:
                # global_index = VarUInt32Field()
                pass

            elif immtype == wasm.immtypes.MemoryImm:
                # flags = VarUInt32Field()
                # offset = VarUInt32Field()
                pass

            elif immtype == wasm.immtypes.CurGrowMemImm:
                # reserved = VarUInt1Field()
                pass

            elif immtype == wasm.immtypes.I32ConstImm:
                # value = VarInt32Field()
                pass

            elif immtype == wasm.immtypes.I64ConstImm:
                # value = VarInt64Field()
                pass

            elif immtype == wasm.immtypes.F32ConstImm:
                # value = UInt32Field()
                pass

            elif immtype == wasm.immtypes.F64ConstImm:
                # value = UInt64Field()
                pass

        return insn.size

    def init_instructions(self):
        # Now create an instruction table compatible with IDA processor module requirements
        insns = []
        for op in wasm.opcodes.OPCODES:
            insns.append({
                'name': op.mnemonic.encode('ascii'),
                'feature': op.flags,
                'cmd': None,          # TODO(wb): add cmt help
            })
            clean_mnem = op.mnemonic.encode('ascii').replace('.', '_').replace('/', '_').upper()
            setattr(self, 'itype_' + clean_mnem, op.id)

        # icode of the last instruction + 1
        # ref: https://github.com/athre0z/wasm/blob/master/wasm/opcodes.py#L198
        #
        #     Opcode(0xbf, 'f64.reinterpret/i64', None, 0),
        self.instruc_end = 0xC0

        # Array of instructions
        self.instruc = insns

        # Icode of return instruction. It is ok to give any of possible return
        # instructions
        self.icode_return = self.itype_RETURN

    def init_registers(self):
        """This function parses the register table and creates corresponding ireg_XXX constants"""

        # Registers definition
        self.reg_names = [
            "SP",
            "CS",
            "DS"
        ]

        # Create the ireg_XXXX constants
        for i in xrange(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i], i)

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.ireg_CS
        self.reg_last_sreg  = self.ireg_DS

        # number of CS register
        self.reg_code_sreg = self.ireg_CS

        # number of DS register
        self.reg_data_sreg = self.ireg_DS

    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.PTRSZ = 4 # Assume PTRSZ = 4 by default
        self.init_instructions()
        self.init_registers()


def PROCESSOR_ENTRY():
    logging.basicConfig(level=logging.DEBUG)
    return wasm_processor_t()
