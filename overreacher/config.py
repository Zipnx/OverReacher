
from typing import Mapping, Optional
from dataclasses import dataclass
from pathlib import Path
import configparser

from .visuals import error, good, info

from shutil import copy as copy_file
from os import makedirs
from os.path import isdir as is_directory
from os.path import exists as file_exists

@dataclass(frozen = True)
class ArgumentDefaults:
    attacks_file: Path
    threads: int
    output_file: str
    http_methods: str
    req_timeout: int
    rate_limit: int
    no_color: bool
    ignore_acac: bool

@dataclass(frozen = True)
class Configuration:
    data_directory: Path
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

def get_data_directory() -> Optional[Path]:
    setup_filepath = Path(__file__).parent.resolve() / 'setup.ini'

    # Make the setup.ini file if the tool is run for the first time
    if not file_exists(setup_filepath):
        default_config_dir()

    # Get the data directory path
    setup = configparser.ConfigParser()
    setup.optionxform = str
    res = setup.read(setup_filepath)
    
    if len(res) == 0:
        error(f'Setup file not found: "{setup_filepath}"')
        return None

    return Path(__file__).parent.resolve() / setup.get('SETUP', 'data_directory', fallback = './data/')


def load_config() -> Optional[Configuration]:
    
    data_directory = get_data_directory()

    if data_directory is None: return None

    config = configparser.ConfigParser()
    config.optionxform = str # Bit hacky but ¯\_(ツ)_/¯
    res = config.read(data_directory / 'config.ini')

    if len(res) == 0:
        error(f'Config file not found: "{data_directory / "config.ini"}"')
        error('If the config is broken, consider running with "--reset-config"')
        return None

    #print(Path(__file__).parent.resolve() / 'setup.ini')
    #print(Path(__file__).parent.resolve() / data_directory / 'config.ini')
    
    attacks_relpath = config.get('DEFAULTS', 'attacks_file', fallback = './attacks.json')

    default_settings = ArgumentDefaults(
        attacks_file = data_directory / attacks_relpath,
        threads = config.getint('DEFAULTS', 'threads', fallback = 8),
        output_file = config.get('DEFAULTS', 'output_file', fallback = ''),
        http_methods = config.get('DEFAULTS', 'http_methods', fallback = 'GET'),
        req_timeout = config.getint('DEFAULTS', 'req_timeout', fallback = 8),
        rate_limit = config.getint('DEFAULTS', 'rate_limit', fallback = 100),
        no_color = config.getboolean('DEFAULTS', 'no_color', fallback = False),
        ignore_acac = config.getboolean('DEFAULTS', 'ignore_acac', fallback = False),
    )

    return Configuration(
        data_directory = data_directory,
        default_args = default_settings,
        default_headers = dict_from_section(config, 'DEFAULT_HEADERS'),
        used_proxies = dict_from_section(config, 'PROXIES'),
    )

def setup_config_dir(directory: Path) -> bool:

    if not is_directory(directory): 
        error('Invalid config location (not a directory)')
        return False
    
    setup_filepath = Path(__file__).parent.resolve() / 'setup.ini'
    default_conf   = Path(__file__).parent.resolve() / 'data/'
    new_directory = directory / '.overreacher/'

    # Make the directory and move default conf files (if it doest exist)
    if not is_directory(new_directory):
        makedirs(new_directory)
        
        # Copy the default files
        copy_file(default_conf / 'attacks.json', new_directory)
        copy_file(default_conf / 'config.ini', new_directory)

    else:
        info('Setting existing config directory')
        # TODO: Check if the required files exist

    # Update the setup.ini
    new_setup = configparser.ConfigParser()
    new_setup.add_section('SETUP')
    new_setup.set('SETUP', 'data_directory', str(directory / '.overreacher/'))

    with open(setup_filepath, 'w') as f:
        new_setup.write(f)

    return True

def default_config_dir() -> None:
    setup_filepath = Path(__file__).parent.resolve() / 'setup.ini'
    confdir = Path(__file__).parent.resolve() / 'data/'

    setup_file = configparser.ConfigParser()
    setup_file.add_section('SETUP')
    setup_file.set('SETUP', 'data_directory', str(confdir.resolve()))

    with open(setup_filepath, 'w') as f:
        setup_file.write(f)

    good('Reset to default configuration path')
