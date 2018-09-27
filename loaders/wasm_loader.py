import idawasm.loader

# for some reason, all names referenced in `idawasm.loader.load_file` must be global,
# so load them here.
from idawasm.loader import *  # NOQA: F401, F403 unable to detect undefined names

accept_file = idawasm.loader.accept_file
load_file = idawasm.loader.load_file
