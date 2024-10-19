
from dataclasses import dataclass
from pathlib import Path
import configparser

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

def load_config() -> Configuration:
    config = configparser.ConfigParser()
    config.read(Path(__file__).parent.parent.resolve() / 'data/config.ini')

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

    return Configuration(default_args = default_settings)

