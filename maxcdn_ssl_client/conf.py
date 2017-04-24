"""
Configuration abstraction for maxcdn-ssl-client
"""

import yaml

class Config(object):
    """
    Object representing a maxcdn-ssl-client configuration file
    """
    # pylint: disable=too-few-public-methods

    __slots__ = ('_config', )

    def __init__(self, file):
        """
        Create a new configuration object from the given configuration file.

        :param str file: File name of the configuration file to parse
        """
        with open(file, "r") as conff:
            self._config = yaml.safe_load(conff)

    def get(self, key, default=None):
        """
        Get a configuration value identified by the given key and return the
        default (or None), if no such key exists in the configuration.

        :param str key: The key to look up
        :param object default: An optional default to return if the key is not present
        """
        try:
            return self._config[key]
        except KeyError:
            return default
