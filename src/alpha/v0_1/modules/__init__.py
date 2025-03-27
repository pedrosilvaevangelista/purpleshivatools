import os
import glob

module_files = glob.glob(os.path.join(os.path.dirname(__file__), "*.py"))
__all__ = [os.path.basename(f)[:-3] for f in module_files if f.endswith(".py") and not f.endswith("__init__.py")]

from importlib import import_module
for module in __all__:
    import_module(f".{module}", package=__name__)
