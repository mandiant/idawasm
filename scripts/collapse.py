import logging
import collections

import wasm
import wasm.decode
import wasm.opcodes
import netnode

import idaapi
import ida_bytes


logger = logging.getLogger('wasm-emu')



def get_type_sort_order(v):
    '''
    when ordering a list of (possibly complex) values, prefer:
      binary-op < memory < global < local-var < i32
    '''
    if isinstance(v, BinaryOperation):
        return 1
    elif isinstance(v, Memory):
        return 2
    elif isinstance(v, GlobalVariable):
        return 3
    elif isinstance(v, LocalVariable):
        return 4
    elif isinstance(v, I32):
        return 5
    else:
        raise ValueError('unexpected value type')


def cmp(a, b):
    '''
    define a general purpose ordering for (possibly complex) values.

    useful when rendering the memory map, which has signature Dict[Any, Any],
     where the key is any of our types or nodes (I32, LocalVarable, etc).
    '''
    at = get_type_sort_order(a)
    bt = get_type_sort_order(b)

    if at != bt:
        return at < bt

    if isinstance(a, I32):
        return a.value < b.value

    elif isinstance(a, LocalVariable):
        return a.local_index < b.local_index

    elif isinstance(a, GlobalVariable):
        return a.global_index < b.global_index

    elif isinstance(a, Memory):
        return cmp(a.address, b.address)

    elif isinstance(a, BinaryOperation):
        if a.operation != b.operation:
            return a.operation < b.operation

        # a.lhs != b.lhs
        if a.lhs < b.lhs or b.lhs < a.lhs:
            return cmp(a.lhs, b.lhs)
        # a.rhs != b.rhs
        elif a.rhs != b.rhs or b.rhs < a.rhs:
            return cmp(a.rhs, b.rhs)

        return False

    else:
        raise ValueError('unexpected value type: ' + str(type(self)))


class I32(object):
    def __init__(self, value):
        self.value = value

    def render(self, ctx={}):
        return '0x{self.value:X}'.format(**locals())

    def __lt__(self, other):
        return cmp(self, other)


class LocalVariable(object):
    def __init__(self, local_index):
        self.local_index = local_index

    def render(self, ctx={}):
        return '{local}'.format(local=render_local(self.local_index, ctx=ctx))

    def __lt__(self, other):
        return cmp(self, other)


class GlobalVariable(object):
    def __init__(self, global_index):
        self.global_index = global_index

    def render(self, ctx={}):
        return '{g}'.format(g=render_global(self.global_index, ctx=ctx))

    def __lt__(self, other):
        return cmp(self, other)


def is_frame_pointer(value, ctx={}):
    return render(value, ctx=ctx) == '$frame_pointer'


class Memory(object):
    def __init__(self, address):
        self.address = address

    def render(self, ctx={}):
        addr = reduce(self.address)
        return 'memory[{addr}]'.format(addr=render(self.address, ctx=ctx))

    def __lt__(self, other):
        return cmp(self, other)


class BinaryOperation(object):
    def __init__(self, operation, lhs, rhs):
        self.operation = operation
        self.lhs = lhs
        self.rhs = rhs

    def render(self, ctx={}):
        return '({lhs} {op} {rhs})'.format(
            lhs=render(self.lhs, ctx=ctx),
            op=self.operation,
            rhs=render(self.rhs, ctx=ctx))

    def __lt__(self, other):
        return cmp(self, other)


class AddOperation(BinaryOperation):
    def __init__(self, lhs, rhs):
        super(AddOperation, self).__init__('+', lhs, rhs)


class SubOperation(BinaryOperation):
    def __init__(self, lhs, rhs):
        super(SubOperation, self).__init__('-', lhs, rhs)


class AndOperation(BinaryOperation):
    def __init__(self, lhs, rhs):
        super(AndOperation, self).__init__('&', lhs, rhs)


class ShlOperation(BinaryOperation):
    def __init__(self, lhs, rhs):
        super(ShlOperation, self).__init__('<<', lhs, rhs)


class ShrOperation(BinaryOperation):
    def __init__(self, lhs, rhs):
        super(ShrOperation, self).__init__('>>', lhs, rhs)


def reduce(value):
    if isinstance(value, BinaryOperation):
        rhs = reduce(value.rhs)
        lhs = reduce(value.lhs)

        if isinstance(value, AddOperation):
            # A + 0 = A
            if isinstance(rhs, I32) and rhs.value == 0:
                return lhs

            # 0 + A = A
            elif isinstance(lhs, I32) and lhs.value == 0:
                return rhs

            # A + B = B + A
            # and we prefer integers on the rhs
            if isinstance(lhs, I32) and not isinstance(rhs, I32):
                lhs, rhs = rhs, lhs

            # (A + B) + C = A + (B + C)
            # and reduce the B + C if constant
            if (isinstance(rhs, I32)
                  and isinstance(lhs, AddOperation)
                  and isinstance(lhs.rhs, I32)):
                return AddOperation(lhs.lhs, I32(lhs.rhs.value + rhs.value))

        return type(value)(lhs, rhs)

    else:
        return value


def render_local(index, ctx={}):

    name = '$local{index:d}'.format(**locals())
    if name in ctx.get('regvars', {}):
        return ctx['regvars'][name]
    else:
        return name


def render_global(index, ctx={}):
    name = '$global{index:d}'.format(**locals())
    if name in ctx.get('globals', {}):
        return ctx['globals'][name]
    else:
        return name


def render(value, ctx={}):
    value = reduce(value)
    if isinstance(value, (I32, LocalVariable, GlobalVariable, Memory)):
        return reduce(value).render(ctx=ctx)
    # render `(frame_pointer + struct_offset)`
    # as `frame_pointer.fieldname`
    elif (isinstance(value, AddOperation)
          and is_frame_pointer(value.lhs, ctx=ctx)
          and isinstance(value.rhs, I32)
          and value.rhs.value in ctx.get('frame', {})):
        return 'frame_pointer.{field}'.format(field=ctx['frame'][value.rhs.value])
    elif isinstance(value, BinaryOperation):
        return reduce(value).render(ctx=ctx)
    else:
        raise NotImplementedError('value type: ' + str(type(value)))


class Emulator:
    def __init__(self, code):
        self.code = code
        self.bc = wasm.decode.decode_bytecode(code)
        self.stack = []
        self.locals = {}
        self.globals = {}
        self.memory = {}

    def push(self, v):
        logger.debug('stack: pushed %s', render(v))
        self.stack.append(v)

    def pop(self):
        v = self.stack[-1]
        logger.debug('stack: popped %s', render(v))
        self.stack = self.stack[:-1]
        return v

    def handle_I32_CONST(self, insn):
        self.push(I32(insn.imm.value))

    def handle_SET_LOCAL(self, insn):
        v = self.pop()
        logger.debug('locals: set %s: %s', render_local(insn.imm.local_index), render(v))
        self.locals[insn.imm.local_index] = v

    def handle_GET_LOCAL(self, insn):
        try:
            v = self.locals[insn.imm.local_index]
        except KeyError:
            v = LocalVariable(insn.imm.local_index)
        self.push(v)

    def handle_SET_GLOBAL(self, insn):
        v = self.pop()
        logger.debug('globals: set %s: %s', render_global(insn.imm.global_index), render(v))
        self.globals[insn.imm.global_index] = v

    def handle_GET_GLOBAL(self, insn):
        try:
            v = self.globals[insn.imm.global_index]
        except KeyError:
            v = GlobalVariable(insn.imm.global_index)
        self.push(v)

    def handle_I32_ADD(self, insn):
        v1 = self.pop()
        v0 = self.pop()

        # V + 0 = V
        if isinstance(v0, I32) and v0.value == 0:
            self.push(v1)
        # 0 + V = V
        elif isinstance(v1, I32) and v1.value == 0:
            self.push(v0)
        if isinstance(v0, I32) and isinstance(v1, I32):
            self.push(I32(v0.value + v1.value))
        else:
            self.push(AddOperation(v0, v1))

    def handle_I32_SUB(self, insn):
        v1 = self.pop()
        v0 = self.pop()

        # V - 0 = V
        if isinstance(v0, I32) and v0.value == 0:
            self.push(v1)
        if isinstance(v0, I32) and isinstance(v1, I32):
            self.push(I32(v0.value - v1.value))
        else:
            self.push(SubOperation(v0, v1))

    def handle_I32_AND(self, insn):
        v1 = self.pop()
        v0 = self.pop()

        # TODO: special case u8 & 0xFF

        if isinstance(v0, I32) and isinstance(v1, I32):
            self.push(I32(v0.value & v1.value))
        else:
            self.push(AndOperation(v0, v1))

    def handle_I32_SHL(self, insn):
        v1 = self.pop()
        v0 = self.pop()

        if isinstance(v0, I32) and isinstance(v1, I32):
            self.push(I32(v0.value << v1.value))
        else:
            self.push(ShlOperation(v0, v1))

    def handle_I32_LOAD8_U(self, insn):
        base = self.pop()
        offset = insn.imm.offset

        if isinstance(base, I32):
            addr = I32(base.value + offset)
        else:
            addr = AddOperation(base, I32(offset))

        if isinstance(addr, I32) and addr.value in self.memory:
            self.push(self.memory[addr.value])
        else:
            self.push(Memory(addr))

    def handle_I32_LOAD(self, insn):
        base = self.pop()
        offset = insn.imm.offset

        if isinstance(base, I32):
            addr = I32(base.value + offset)
        else:
            addr = AddOperation(base, I32(offset))

        if (isinstance(addr, I32)
              and addr.value in self.memory
              and addr.value + 1 in self.memory
              and addr.value + 2 in self.memory
              and addr.value + 3 in self.memory):

            v = (self.memory[addr.value] +
                 (self.memory[addr.value + 1] << 8) +
                 (self.memory[addr.value + 2] << 16) +
                 (self.memory[addr.value + 3] << 24))
            self.push(I32(v))
        else:
            self.push(Memory(addr))

    def handle_I32_STORE8(self, insn):
        value = self.pop()
        base = self.pop()
        offset = insn.imm.offset

        if isinstance(base, I32):
            addr = I32(base.value + offset)
        else:
            addr = AddOperation(base, I32(offset))

        if isinstance(value, I32):
            v = I32(value.value & 0xFF)
        else:
            v = AndOperation(value, I32(0xFF))

        if isinstance(addr, I32):
            self.memory[addr.value] = v
        else:
            # ew: symbolic address for memory?
            self.memory[addr] = v

    def handle_I32_STORE(self, insn):
        value = self.pop()
        base = self.pop()
        offset = insn.imm.offset

        if isinstance(base, I32):
            addr = I32(base.value + offset)
        else:
            addr = AddOperation(base, I32(offset))

        if isinstance(value, I32):
            v0 = I32(value.value & 0xFF)
            v1 = I32((value.value & 0xFF00) >> 8)
            v2 = I32((value.value & 0xFF0000) >> 16)
            v3 = I32((value.value & 0xFF000000) >> 24)
        else:
            v0 = AndOperation(value, I32(0xFF))
            v1 = ShrOperation(AndOperation(value, I32(0xFF)), I32(8))
            v2 = ShrOperation(AndOperation(value, I32(0xFF00)), I32(16))
            v3 = ShrOperation(AndOperation(value, I32(0xFF0000)), I32(24))

        if isinstance(addr, I32):
            self.memory[addr.value] = v0
            self.memory[addr.value + 1] = v1
            self.memory[addr.value + 2] = v2
            self.memory[addr.value + 3] = v3

        else:
            # ew: symbolic address for memory?
            # TODO: need to reduce here for symbolic addresses to match
            self.memory[AddOperation(addr, I32(0))] = v0
            self.memory[AddOperation(addr, I32(1))] = v1
            self.memory[AddOperation(addr, I32(2))] = v2
            self.memory[AddOperation(addr, I32(3))] = v3

    def handle_DEFAULT(self, insn):
        raise NotImplementedError('instruction: {insn:s}'.format(**locals()))

    def handle_insn(self, insn):
        logger.debug('trace: %s', insn.op.mnemonic)
        handler = {
            wasm.opcodes.OP_I32_CONST: self.handle_I32_CONST,
            wasm.opcodes.OP_I32_ADD: self.handle_I32_ADD,
            wasm.opcodes.OP_I32_SUB: self.handle_I32_SUB,
            wasm.opcodes.OP_I32_AND: self.handle_I32_AND,
            wasm.opcodes.OP_I32_SHL: self.handle_I32_SHL,
            wasm.opcodes.OP_I32_LOAD: self.handle_I32_LOAD,
            wasm.opcodes.OP_I32_LOAD8_U: self.handle_I32_LOAD8_U,
            wasm.opcodes.OP_I32_STORE: self.handle_I32_STORE,
            wasm.opcodes.OP_I32_STORE8: self.handle_I32_STORE8,
            wasm.opcodes.OP_SET_LOCAL: self.handle_SET_LOCAL,
            wasm.opcodes.OP_GET_LOCAL: self.handle_GET_LOCAL,
            wasm.opcodes.OP_SET_GLOBAL: self.handle_SET_GLOBAL,
            wasm.opcodes.OP_GET_GLOBAL: self.handle_GET_GLOBAL,
        }.get(insn.op.id, self.handle_DEFAULT)
        handler(insn)

    def run(self):
        for insn in self.bc:
            self.handle_insn(insn)

    def render(self, ctx={}):
        ret = []

        if self.globals:
            ret.append('globals:')
            for g in sorted(self.globals.keys()):
                ret.append('  ' + render_global(g, ctx) + ': ' + render(self.globals[g], ctx))

        if self.locals:
            ret.append('locals:')
            for l in sorted(self.locals.keys()):
                ret.append('  ' + render_local(l, ctx) + ': ' + render(self.locals[l], ctx))

        if self.stack:
            ret.append('stack:')
            for index, v in enumerate(reversed(self.stack)):
                ret.append('  {index:d}: '.format(**locals()) + render(v, ctx=ctx))

        if self.memory:
            ret.append('memory:')
            for addr, v in sorted([(k, v) for k, v in self.memory.items()]):
                ret.append('  {addr:s}: '.format(addr=render(addr, ctx=ctx)) + render(v, ctx=ctx))

        return '\n'.join(ret)


def main():
    is_selected, sel_start, sel_end = idaapi.read_selection()
    if not is_selected:
        logger.error('range must be selected')
        return -1

    sel_end = idc.NextHead(sel_end)

    buf = ida_bytes.get_bytes(sel_start, sel_end - sel_start)
    if buf is None:
        logger.error('failed to fetch instruction bytes')
        return -1

    f = idaapi.get_func(sel_start)
    if f != idaapi.get_func(sel_end):
        logger.error('range must be within a single function')
        return -1

    # find mappings from "$localN" to "custom_name"
    regvars = {}
    for i in range(0x1000):
        regvar = idaapi.find_regvar(f, sel_start, '$local%d' % (i))
        if regvar is None:
            continue
        regvars[regvar.canon] = regvar.user

        if len(regvars) >= f.regvarqty:
            break

    globals_ = {}
    for i, offset in netnode.Netnode('$ wasm.offsets')['globals'].items():
        globals_['$global' + i] = ida_name.get_name(offset)

    frame = {}
    if f.frame != idc.BADADDR:
        names = set([])
        for i in range(idc.GetStrucSize(f.frame)):
            name = idc.GetMemberName(f.frame, i)
            if not name:
                continue
            if name in names:
                continue
            frame[i] = name
            names.add(name)

    emu = Emulator(buf)
    emu.run()
    print(emu.render(ctx={
        'regvars': regvars,
        'frame': frame,
        'globals': globals_,
    }))


logging.basicConfig(level=logging.DEBUG)
main()
