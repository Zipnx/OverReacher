
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from pathlib import Path
import configparser

from .visuals import error

@dataclass(frozen = True)
class ArgumentDefaults:
    attacks_file: str
    threads: int
    output_file: str
    http_methods: str
    req_timeout: int
    rate_limit: int
    no_color: bool
    ignore_acac: bool

@dataclass(frozen = True)
class Configuration:
    default_args: ArgumentDefaults
    default_headers: Mapping
    used_proxies: Mapping

def dict_from_section(config: configparser.ConfigParser, section_name: str) -> Mapping[str, str]:
    '''
    Get a dict from a config section. Used for the default headers and also proxies
    Will return an empty dict if the section does not exist
    WARNING: All the values are assumed to be strings!

    Args:
        config (ConfigParser): Parser object
        section_name (str): Section name to use

    Returns:
        Mapping[str, str]: Resulting dict
    '''

    if not config.has_section(section_name): return {}

    result = {}

    for key in config[section_name].keys():
        result[key] = config.get(section_name, key)
        
    return result

def load_config() -> Configuration | None:
    setup_filepath = Path(__file__).parent.resolve() / 'setup.ini'

    # Get the data directory path
    setup = configparser.ConfigParser()
    setup.optionxform = str
    res = setup.read(setup_filepath)
    
    if len(res) == 0:
        error(f'Setup file not found: "{setup_filepath}"')
        return None

    data_directory = Path(__file__).parent.resolve() / setup.get('SETUP', 'data_directory', fallback = './data/')

    config = configparser.ConfigParser()
    config.optionxform = str # Bit hacky but ¯\_(ツ)_/¯
    res = config.read(data_directory / 'config.ini')

    if len(res) == 0:
        error(f'Config file not found: "{data_directory / "config.ini"}"')
        return None

    #print(Path(__file__).parent.resolve() / 'setup.ini')
    #print(Path(__file__).parent.resolve() / data_directory / 'config.ini')

    default_settings = ArgumentDefaults(
        attacks_file = config.get('DEFAULTS', 'attacks_file', fallback = 'data/attacks.json'),
        threads = config.getint('DEFAULTS', 'threads', fallback = 8),
        output_file = config.get('DEFAULTS', 'output_file', fallback = ''),
        http_methods = config.get('DEFAULTS', 'http_methods', fallback = 'GET'),
        req_timeout = config.getint('DEFAULTS', 'req_timeout', fallback = 8),
        rate_limit = config.getint('DEFAULTS', 'rate_limit', fallback = 100),
        no_color = config.getboolean('DEFAULTS', 'no_color', fallback = False),
        ignore_acac = config.getboolean('DEFAULTS', 'ignore_acac', fallback = False),
    )

    return Configuration(
        default_args = default_settings,
        default_headers = dict_from_section(config, 'DEFAULT_HEADERS'),
        used_proxies = dict_from_section(config, 'PROXIES'),
    )


