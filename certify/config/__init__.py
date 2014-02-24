import sys
import os.path
import logging
import logging.config
import logging.handlers
import warnings
import ConfigParser

from certify import exc
from certify.config.model import MinionConfig, CMConfig

DEFAULT_CERTMASTER_CONFIG_FILE = '/etc/certify/certify.cfg'
DEFAULT_MINION_CONFIG_FILE = '/etc/certify/minion.cfg'

minion_config = MinionConfig()
certify_config = CMConfig()

def _init_config(configfile, config_obj, section='main'):
    confparser = ConfigParser.ConfigParser()
    read = None
    if configfile and os.path.exists(configfile):
        read = confparser.read(configfile)
    if read:
        config_obj.populate(confparser, section)
    else:
        raise exc.ConfigError("Unable to read config file: %s" % (configfile,))
    
def init_certify_config(configfile):
    global certify_config
    _init_config(configfile, certify_config)
    
def init_minion_config(configfile):
    global minion_config
    _init_config(configfile, minion_config)

def init_logging(configfile, console_level=None):
    """
    Initializes the logging subsystem, giving preference to the configparser-format log file
    configuration, and falling back to classic certify logfile/loglevel specification.
    
    The `console_level` parameter will add an additional stdout console handler at specified level.
    """
    if configfile and os.path.exists(configfile):
        testcfg = ConfigParser.SafeConfigParser(defaults={'log_level': logging.INFO})
        read = testcfg.read(configfile)
        use_fileconfig = (read and testcfg.has_section('loggers'))
   
        if use_fileconfig:
            logging.config.fileConfig(configfile)
        else:
            log_file = testcfg.get('main', 'log_file')
            log_level_str = testcfg.get('main', 'log_level')
            log_level = getattr(logging, log_level_str.upper(), None)
            if not isinstance(log_level, int):
                warnings.warn("Invalid log level specified (defaulting to INFO): %s" % log_level_str)
                log_level = logging.INFO
        
            if log_file == 'syslog':
                handler = logging.handlers.SysLogHandler(('/dev/log',))
                handler.setLevel(log_level)
                handler.setFormatter(logging.Formatter('%(name)s - %(levelname)s - %(message)s'))
                logging.getLogger().addHandler(handler)
            else:
                # Standard FileHandler
                fmt = '%(asctime)s %(name)s - %(levelname)s - %(message)s'
                logging.basicConfig(filename=log_file, level=log_level, format=fmt)
            
        if console_level:
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(console_level)
            logging.getLogger().addHandler(ch)
            
    else:
        warnings.warn("Could not read configuration file (%s), creating a default logger." % configfile)
        fmt = '%(asctime)s %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(level=logging.INFO, format=fmt)
