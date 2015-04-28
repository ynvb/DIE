import imp
from os import path, environ
import sys


DIE_DIR = environ["DieDir"]
DIE_NAME = "DIE.py"

sys.path.append(DIE_DIR)

plugin_path = path.join(DIE_DIR, DIE_NAME)

plugin = imp.load_source(__name__, plugin_path)

# Export the plugin entry
PLUGIN_ENTRY = plugin.PLUGIN_ENTRY