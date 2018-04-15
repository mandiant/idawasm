import struct

import wasm
import wasm.decode
import wasm.wasmtypes

import idc
import idaapi


PLFM_WASM = 0x8069


class wasm_processor_t(idaapi.processor_t):
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
    }


    # ----------------------------------------------------------------------
    # Processor module callbacks
    #
    # ----------------------------------------------------------------------
    def notify_get_frame_retsize(self, func_ea):
        """
        Get size of function return address in bytes
        """
        return 16

    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        return None

    def notify_can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: bool
        """
        return False

    def notify_is_align_insn(self, ea):
        """
        Is the instruction created only for alignment purposes?
        Returns: number of bytes in the instruction
        """
        return False

    def notify_newfile(self, filename):
        print('notify newfile')

    def notify_oldfile(self, filename):
        print('notify oldfile')

    def notify_out_header(self, ctx):
        """function to produce start of disassembled text"""
        print('notify out header')

    def notify_may_be_func(self, insn, state):
        """
        can a function start here?
        the instruction is in 'insn'
          arg: state -- autoanalysis phase
            state == 0: creating functions
                  == 1: creating chunks
          returns: probability 0..100
        """
        return 0

    def check_thunk(self, addr):
        """
        Check for thunk at addr
        dd fnaddr - (addr+4), 0, 0, 0
        """
        return None

    def handle_operand(self, insn, op, isRead):
        return

    def add_stkpnt(self, insn, pfn, v):
        return

    def trace_sp(self, insn):
        """
        Trace the value of the SP and create an SP change point if the current
        instruction modifies the SP.
        """
        return

    def notify_emu(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        return 1

    def notify_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        return True

    def out_mnem(self, ctx):
        '''
        Generate the instruction mnemonics
        '''
        return

   def notify_out_insn(self, ctx):
       '''
        Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
       '''
        return

    def notify_ana(self, insn):
        """
        Decodes an instruction into insn
        """
        return 0

    def decode(self, insn, opbyte):
        return True

    def init_instructions(self):
        class idef:
            def __init__(self, name, cf, d, cmt=None):
                '''
                Args:
                  name (str): name of instruction.
                  cf (int): canonical flags used by IDA, like CF_*.
                  df (function): decoder.
                  cmd (str): instruction comment.
                '''
                self.name = name
                self.cf  = cf
                self.d   = d
                self.cmt = cmt

        self.itable = {
            op.id: idef(name=op.mnemonic, cf=op.flags, d=self.decode)
             for op in wasm.opcodes.OPCODES
        }

        insns = []
        i = 0
        for x in self.itable.values():
            d = dict(name=x.name, feature=x.cf)
            if x.cmt != None:
                d['cmt'] = x.cmt
            insns.append(d)
            setattr(self, 'itype_' + x.name.upper().replace('.', '_').replace('/', '_'), i)
            i += 1

        # icode of the last instruction + 1
        # ref: https://github.com/athre0z/wasm/blob/master/wasm/opcodes.py#L198
        self.instruc_end = 0xC0

        self.instruc = insns

        self.icode_return = self.itype_RETURN

    def init_registers(self):
        """This function parses the register table and creates corresponding ireg_XXX constants"""

        self.reg_names = [
            "CS",  # fake
            "DS",  # fake
        ]

        # Create the ireg_XXXX constants
        for i in xrange(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i], i)

        # processor doesnt actually have these.
        self.reg_first_sreg = self.ireg_CS
        self.reg_last_sreg  = self.ireg_DS
        self.reg_code_sreg = self.ireg_CS
        self.reg_data_sreg = self.ireg_DS

    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.PTRSZ = 4  # wasm32
        self.init_instructions()
        self.init_registers()


def PROCESSOR_ENTRY():
    return wasm_processor_t()
