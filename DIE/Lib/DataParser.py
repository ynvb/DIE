

from DIE.Lib.DataPluginBase import DataPluginBase
import logging
import idaapi
import idc
import sys

try:
    # TODO: Is singleton really required here? python modules are basically singleton by design
    from yapsy.PluginManager import PluginManagerSingleton
except ImportError, err:
    idaapi.msg("Yapsy not installed (please use 'pip install yapsy' or equivalent : %s\n", err)
    # TODO: does this not kill IDA? Instead, the error should be propagated to the plugin initialization.
    sys.exit(1)

# TODO: better use new style classes
class DataParser():
    """
    Data parser is a class for parsing raw runtime values.
    """

    def __init__(self):

        self.logger = logging.getLogger(__name__)

        # type_parsers is a dictionary that maps type names to the parsers that support them.
        # this is done in order to speedup parser lookups and avoid iterating the entire parser list
        self.type_parsers = {}

        self.pManager = PluginManagerSingleton.get()            # Plugin manager

    def set_plugin_path(self, plugin_path):
        """
        Set the data parser plugin path
        @param plugin_path: full path of data-parser root directory
        @return:
        """

        self.pluginLocation = plugin_path
        self.pManager.setPluginPlaces([self.pluginLocation])    # Set plugin directory
        self.pManager.setCategoriesFilter({"ParserPlugins": DataPluginBase})

        self.logger.info("Plugin path is set to %s", plugin_path)

    def loadPlugins(self):
        """
        Load\Reload all plugins found in the plugin location.
        """
        self.logger.info("Loading Plugins from %s", self.pluginLocation)

        self.pManager.collectPlugins()

        all_plugins = self.pManager.getAllPlugins()
        if len(all_plugins) == 0:
            idaapi.msg("Warning - No Plugins were loaded!\n")
            self.logger.error("No plugins were loaded")

        for pluginInfo in all_plugins:

            # TODO: Validate plugins!
            self.logger.info("Loading plugin %s", pluginInfo.name)

            if pluginInfo.name == "headers":
                # headers is an illegal plugin name (see get_parser_list)
                continue

            # Set a type name normalizing function
            pluginInfo.plugin_object.initPlugin(self.typeName_norm)
            self.pManager.activatePluginByName(pluginInfo.name)

            # Add type to type_parser dict for quick lookups
            suported_types = pluginInfo.plugin_object.getSupportedTypes()

            if suported_types is not None:
                self.addTypeParser(suported_types, pluginInfo.plugin_object)

    def deactivatePlugin(self, pluginInfo):
        """
        Deactivate a plugin
        @param pluginInfo: deactivated plugin plugininfo object
        @return:
        """
        # Deactivate plugin
        self.pManager.deactivatePluginByName(pluginInfo.name)

        # Remove from type_parsers
        for stype in self.type_parsers:
            if pluginInfo.plugin_object in self.type_parsers[stype]:
                self.type_parsers[stype].remove(pluginInfo.plugin_object)

    def activatePlugin(self, pluginInfo):
        """
        Activate a plugin
        @param pluginInfo: activated plugin plugininfo object
        @return:
        """
        # Run plugin initialization
        pluginInfo.plugin_object.initPlugin(self.typeName_norm)

        # Activate Plugin
        self.pManager.activatePluginByName(pluginInfo.name)

    def get_parser_list(self):
        """
        Query available parsers
        @return: Returns a dictionary of all available parsers and their data.
                 The dictionary key is the parser name, and value is a list of available data in the following format:
                    Plugin1 -> [Plugin1 Description, Plugin1 Version,
                    Plugin2 -> [Plugin2 Description, Plugin2 Version, ...]
                A special key named "headers" represents the type names of the returned columns
        """
        parser_list = {}

        # TODO: use classes or named tuples
        parser_list["headers"] = ["Description", "Version", "State", "Author"]

        for plugin in self.pManager.getAllPlugins():
            parser_list[plugin.name] = [plugin.description, plugin.version, plugin.is_activated, plugin.author]

        return parser_list

    def addTypeParser(self, supported_types, parser_plugin):
        """
        Add an entry to the type_parser dictionary
        @param supported_types: a list of supported type strings
        @param parser_plugin: parser plugin object
        """
        for stype, sparams in supported_types:
            if stype in self.type_parsers:
                self.type_parsers[stype].append(parser_plugin)
            else:
                self.type_parsers[stype] = [parser_plugin]

    def ParseData(self, rawData, type=None, loc=None, custom_parser=None):
        """
        Parse Data
        @param rawData: The raw data to be parsed
        @param type: The data type (If unknown should be None)
        @param loc: raw value (memory) location
        @param custom_parser: A custom parser to use.
        @return: A list of ParsedValue objects (containing the guessed\exact parsed values)
        """
        parsedValues = []

        try:
            # If custom parser was defined
            if custom_parser is not None:
                custom_parser.run(rawData, type, match_override=True)
                ret_vals = custom_parser.getParsedValues()
                parsedValues.extend(ret_vals)

                return parsedValues

            # if type is known, try to look it up in the parser_type dict
            if type is not None:
                type_name = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, type, '', '')
                type_name = self.typeName_norm(type_name)

                if type_name in self.type_parsers:
                    for parser_plugin in self.type_parsers[type_name]:
                        parser_plugin.run(rawData, type)
                        ret_vals = parser_plugin.getParsedValues()
                        parsedValues.extend(ret_vals)

                    return parsedValues

            # Otherwise, the entire plugin list has to be iterated
            for pluginInfo in self.pManager.getAllPlugins():
                if pluginInfo.is_activated:
                    pluginInfo.plugin_object.run(rawData, type)
                    ret_vals = pluginInfo.plugin_object.getParsedValues()
                    parsedValues.extend(ret_vals)

            return parsedValues

        except Exception as ex:
            self.logger.exception("Error while parsing data: %s", ex)


    def typeName_norm(self, type_name):
        """
        Builds and returns a normalized type string.
        Normalization deletes all space characters and changes to uppercase.
        @param type_name: Type name string (e.g "CONST CHAR *")
        @return: a normalized type name
        """
        if not type_name:
            return None

        type_name = type_name.upper()
        type_name = type_name.replace(" ", "")

        return type_name

### a global dataParser object.
### This should basically be enough in order to create a singleton object, since of the way Python modules are
### loaded (reloading of a module should never be preformed..)

# TODO: Read from configuration file
#config = DieConfig.get_config()

idaapi.msg("[2] Loading data parsers\n")
#_dataParser = DataParser("C:\Users\yanivb\Desktop\Workspace\Projects\DIE\Plugins\DataParsers")
#_dataParser = DataParser(config.data_parser_path)
_dataParser = DataParser()

# Just in case this will someday be a full singleton implementation
def getParser():
    """
    Get a parser instance
    @return: DataParser instance
    """
    return _dataParser








