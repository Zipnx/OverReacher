
import sys
from dataclasses import dataclass, field
from argparse import ArgumentParser, Namespace

@dataclass(init = True)
class ScanArguments:
    targets: list
    threads: int        = 8
    output_file: str    = ''
    output_format: str  = 'txt'
    http_methods: list  = field(default_factory = lambda: ['GET', 'POST', 'OPTIONS'])
    http_headers: dict  = field(default_factory = lambda: {})
    color_enabled: bool = True
    max_rps: int        = 100

def parse_arguments() -> Namespace:
    parser = ArgumentParser(description = 'OverReacher - A convenient CORS scanner tool')

    parser.add_argument('-u', '--urls',   type = str, help = 'Comma separated list of targets')
    parser.add_argument('-i', '--inputs', type = str, help = 'File with a list of targets')
    parser.add_argument('-o', '--output', type = str, help = 'Path to an output file')
    parser.add_argument('-f', '--format', type = str, help = 'Save format (DEFAULT=txt)')
    
    parser.add_argument('-m', '--methods', type = str, default = 'GET,POST,OPTIONS',
        help = 'Comma seperated http methods to use (DEFAULT=GET,POST,OPTIONS)'
    )

    parser.add_argument('-H', '--header', type = str, action = 'append',
        help = 'Header to be added to requests (can be used multiple times)'
    )

    parser.add_argument('-t', '--threads', type = int, default = 8,
        help = 'Number of threads to use (DEFAULT=8)'
    )
    
    parser.add_argument('-r', '--rate',    type = int, default = 100,
        help = 'Rate of max requests per second (DEFAULT=100)'
    )

    parser.add_argument('--no-color',      action = 'store_true',
        help = 'Disable color (the NO_COLOR env variable works too)'
    )

    args = parser.parse_args()

    return args

def get_arguments() -> ScanArguments | None:

    args = parse_arguments()

    return ScanArguments(['127.0.0.1'])
