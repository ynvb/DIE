__author__ = 'yanivb'
import logging
import os
import ConfigParser

import idaapi

class DIE_Config():
    """
    DIE configuration class
    """

    def __init__(self):

        self.logger = logging.getLogger(__name__)
        self.config_parser = ConfigParser.ConfigParser()
        self.config = {}

    def load_configuration(self, config_file_name):
        """
        Load configuration file
        @return: True if configuration was loaded successfully, otherwise False
        """
        try:

            print "Loading configuration file..."

            # Load custom configuration file
            if not os.path.isfile(config_file_name):
                self.logger.error("Config file not found: %s", config_file_name)
                if not self.make_default_config_file(config_file_name):
                    return False

            # Read and parse configuration file
            self.logger.info("Loading Configuration.")
            self.config_parser.read(config_file_name)

            # Set the global config object.
            for section in self.config_parser.sections():
                self.config[section] = {}
                options = self.config_parser.options(section)
                for option in options:
                    try:
                        value = self.config_parser.get(section, option)
                        self.config[section][option] = value
                        self.logger.info("Loaded config section: %s, option: %s, value: %s", section, option, value)

                    except Exception as ex:
                        self.config[section][option] = None
                        self.logger.info("Failed to load config section: %s, option: %s. %s", section, option, ex)

            # If no configuration was loaded, quit.
            if len(self.config) == 0:
                self.logger.error("No configuration found.")
                return False
            else:
                self.logger.info("Configuration loaded successfully")
                return True

        except Exception as ex:
            self.logger.error("Failed to load configuration: %s", ex)
            return False

    def save_configuration(self, config_file_name):
        """
        Save configuration file
        """
        # Save configuration file
        self.logger.info("Saving Configuration.")

        print "Saving configuration file"

        self.config_parser.set("DebugValues", "is_deref", self.config["DebugValues"]["is_deref"])
        self.config_parser.set("DebugValues", "is_raw", self.config["DebugValues"]["is_raw"])
        self.config_parser.set("DebugValues", "is_parse", self.config["DebugValues"]["is_parse"])
        self.config_parser.set("DebugValues", "is_array", self.config["DebugValues"]["is_array"])
        self.config_parser.set("DebugValues", "is_container", self.config["DebugValues"]["is_container"])

        self.config_parser.set("FunctionContext", "get_func_args", self.config["FunctionContext"]["get_func_args"])

        self.config_parser.set("Debugging", "max_func_call", self.config["Debugging"]["max_func_call"])
        self.config_parser.set("Debugging", "max_deref_depth", self.config["Debugging"]["max_deref_depth"])
        self.config_parser.set("Debugging", "code_discovery", self.config["Debugging"]["code_discovery"])

        with open(config_file_name, 'wb') as config_file:
            self.config_parser.write(config_file)

    def make_default_config_file(self, config_file_name):
        """
        Create a default configuration file
        """
        try:

            print "Configuration file not found, creating a default configfile"
            self.logger.info("Generating a default configuration file.")
            config_parser = ConfigParser.ConfigParser()

            config_parser.add_section("DebugValues")
            config_parser.add_section("FunctionContext")
            config_parser.add_section("Debugging")


            config_parser.set("Debugging", "max_func_call", '20')
            config_parser.set("Debugging", "max_deref_depth", '3')
            config_parser.set("Debugging", "code_discovery", "0")

            config_parser.set("FunctionContext", "get_func_args", "1")

            config_parser.set("DebugValues", "is_raw", "1")
            config_parser.set("DebugValues", "is_parse", "1")
            config_parser.set("DebugValues", "is_array", "1")
            config_parser.set("DebugValues", "is_container", "1")
            config_parser.set("DebugValues", "is_deref", "1")

            with open(config_file_name, 'wb') as config_file:
                config_parser.write(config_file)

            return True

        except Exception as ex:
            print "Error while creating default config file: %s" %ex
            logging.error("Failed to create default configuration file: %s", ex)
            return False


#############################################################################
#                            Main Properties
#############################################################################
    # @property
    # def data_parser_path(self):
    #     """
    #     Path of data parser root directory
    #     """
    #     try:
    #         return self.config["Main"]["data_parser_path"]
    #     except:
    #         return None
    #
    # @property
    # def installation_path(self):
    #     """
    #     Installation path of the die plugin
    #     """
    #     try:
    #         return self.config["Main"]["installation_path"]
    #     except:
    #         return None


#############################################################################
#                           DebugValues Properties
#############################################################################

    @property
    def is_deref(self):
        try:
            value = self.config["DebugValues"]["is_deref"]
            if value == "1":
                return True
            return False
        except:
            return True

    def set_deref(self, value):
        try:
            if value:
                self.config["DebugValues"]["is_deref"] = "1"
            else:
                self.config["DebugValues"]["is_deref"] = "0"

        except Exception as ex:
            self.logger.error("Failed to set is_deref value: %s", ex)
            self.config["DebugValues"]["is_deref"] = "1"

    @property
    def is_container(self):
        try:
            value = self.config["DebugValues"]["is_container"]
            if value == "1":
                return True
            return False
        except:
            return True

    def set_container(self, value):
        try:
            if value:
                self.config["DebugValues"]["is_container"] = "1"
            else:
                self.config["DebugValues"]["is_container"] = "0"

        except Exception as ex:
            self.logger.error("Failed to set is_container value: %s", ex)
            self.config["DebugValues"]["is_container"] = "1"

    @property
    def is_array(self):
        try:
            value = self.config["DebugValues"]["is_array"]
            if value == "1":
                return True
            return False
        except:
            return True

    def set_array(self, value):
        try:
            if value:
                self.config["DebugValues"]["is_array"] = "1"
            else:
                self.config["DebugValues"]["is_array"] = "0"

        except Exception as ex:
            self.logger.error("Failed to set is_array value: %s", ex)
            self.config["DebugValues"]["is_array"] = "1"

    @property
    def is_parse(self):
        try:
            value = self.config["DebugValues"]["is_parse"]
            if value == "1":
                return True
            return False
        except:
            return True

    def set_parse(self, value):
        try:
            if value:
                self.config["DebugValues"]["is_parse"] = "1"
            else:
                self.config["DebugValues"]["is_parse"] = "0"

        except Exception as ex:
            self.logger.error("Failed to set is_parse value: %s", ex)
            self.config["DebugValues"]["is_parse"] = "1"

    @property
    def is_raw(self):
        try:
            value = self.config["DebugValues"]["is_raw"]
            if value == "1":
                return True
            return False
        except:
            return True

    def set_raw(self, value):
        try:
            if value:
                self.config["DebugValues"]["is_raw"] = "1"
            else:
                self.config["DebugValues"]["is_raw"] = "0"

        except Exception as ex:
            self.logger.error("Failed to set is_raw value: %s", ex)
            self.config["DebugValues"]["is_raw"] = "1"

#############################################################################
#                           FunctionContext Properties
#############################################################################

    @property
    def get_func_args(self):
        try:
            value = self.config["FunctionContext"]["get_func_args"]
            if value == "1":
                return True
            return False
        except:
            return True

    def set_func_args(self, value):
        try:
            if value:
                self.config["FunctionContext"]["get_func_args"] = "1"
            else:
                self.config["FunctionContext"]["get_func_args"] = "0"

        except Exception as ex:
            self.logger.error("Failed to set get_func_args value: %s", ex)
            self.config["FunctionContext"]["get_func_args"] = "1"



#############################################################################
#                           Debugging Properties
#############################################################################

    @property
    def max_func_call(self):
        try:
            return int(self.config["Debugging"]["max_func_call"])
        except:
            return 100

    def set_max_func_call(self, value):
        try:
            self.config["Debugging"]["max_func_call"] = value

        except Exception as ex:
            self.logger.error("Failed to set max_func_call value: %s", ex)
            self.config["Debugging"]["max_func_call"] = 100

    @property
    def max_deref_depth(self):
        try:
            return int(self.config["Debugging"]["max_deref_depth"])
        except:
            return 3

    def set_max_deref_depth(self, value):
        try:
            self.config["Debugging"]["max_deref_depth"] = value

        except Exception as ex:
            self.logger.error("Failed to set max_deref_depth value: %s", ex)
            self.config["Debugging"]["max_deref_depth"] = 3

    @property
    def code_discovery(self):
        try:
            value = self.config["debugging"]["code_discovery"]
            if value == 1:
                return True
            return False

        except:
            return False

    def set_code_discovery(self, value):
        try:
            self.config["Debugging"]["code_discovery"] = value

        except Exception as ex:
            self.logger.error("Failed to set code discovery value: %s", ex)
            self.config["Debugging"]["code_discovery"] = 0

#############################################################################
# DIE Directories

    @property
    def install_path(self):
        """
        DIE Installation path
        """
        return idaapi.idadir("plugins\DIE")

    @property
    def icons_path(self):
        """
        DIE icons path
        """
        icons_path = self.install_path + "\\Icons"
        return icons_path

    @property
    def parser_path(self):
        """
        DIE Parser path
        """
        parser_path = self.install_path + "\\Plugins\\DataParsers"
        return parser_path



#############################################################################
#                              Singleton
#############################################################################

_config_parser = DIE_Config()

def get_config():
    """
    Return a singleton instance of the global configuration object
    """
    return _config_parser