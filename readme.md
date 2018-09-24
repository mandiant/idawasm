# idawasm

These IDA Pro plugins add support for loading and disassembling WebAssembly modules.


Features:

  - control flow reconstruction and graph mode
  - code and data cross references
  - globals, function parameters, local variables, etc. can be renamed
  - auto-comment hint suport


## installation

There are two steps to install this loader and processor:

 1) install the python module:

    python.exe setup.py install
       
 2) install the IDA plugins
  a) manually copy the loader:

    mv loaders\wasm_loader.py %IDADIR%\loaders\wasm.py

  b) manually copy the processor:

    mv procs\wasm_processor.py %IDADIR%\procs\wasm.py


Whenever you update this project, you'll need to update the python module, but shouldn't have to touch the loader and processor files.


## acknowledgements

This project relies on the [athre0z/wasm](https://github.com/athre0z/wasm) WebAssembly decoder and disassembler library for Python.
