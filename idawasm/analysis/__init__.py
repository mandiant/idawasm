import abc

class Analyzer:
    '''
    An analyzer performs analysis tasks on a new database,
     possibly applying types, comments, etc.
    '''
    __metaclass__ = abc.ABCMeta

    def __init__(self, proc):
        '''
        args:
          proc (idawasm.wasm_processor_t): the WebAssembly processor.
        '''
        self.proc = proc

    @abc.abstracemethod
    def taste(self):
        '''
        detect if this analyzer should run on the current database.

        returns:
          bool: True if the analyzer should be run.
        '''

    @abc.abstracemethod
    def analyze(self):
        '''
        perform the analysis on the current database.

        returns:
          None: the analysis is applied to the .idb as side effects.
        '''
        raise NotImplementedError()
