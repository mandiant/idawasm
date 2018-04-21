import wasm
import wasm.decode
import wasm.wasmtypes


# decoded from VarInt7
WASM_TYPE_I32 = -1
WASM_TYPE_I64 = -2
WASM_TYPE_F32 = -3
WASM_TYPE_F64 = -4
# TODO(wb): check
WASM_TYPE_EMPTY = 0xFFFFFFC0

WASM_TYPE_NAMES = {
    WASM_TYPE_I32: 'i32',
    WASM_TYPE_I64: 'i64',
    WASM_TYPE_F32: 'f32',
    WASM_TYPE_F64: 'f64',
    WASM_TYPE_EMPTY: 'empty',
}

WASM_SECTION_NAMES = {
    wasm.wasmtypes.SEC_TYPE: 'types',
    wasm.wasmtypes.SEC_IMPORT: 'imports',
    wasm.wasmtypes.SEC_FUNCTION: 'functions',
    wasm.wasmtypes.SEC_TABLE: 'tables',
    wasm.wasmtypes.SEC_MEMORY: 'memory',
    wasm.wasmtypes.SEC_GLOBAL: 'globals',
    wasm.wasmtypes.SEC_EXPORT: 'exports',
    wasm.wasmtypes.SEC_START: 'starts',
    wasm.wasmtypes.SEC_ELEMENT: 'elements',
    wasm.wasmtypes.SEC_CODE: 'code',
    wasm.wasmtypes.SEC_DATA: 'data',
}
