
from typing import List, MutableMapping, Optional

import sys
from pathlib import Path
from dataclasses import dataclass, field
from argparse import ArgumentParser, Namespace

from .config import Configuration, ArgumentDefaults
from .utilities import read_urls_file
from .utilities import filter_urls, read_urls_stdin, is_file
from .visuals import info,good,error,warn

@dataclass(init = True)
class ScanArguments:
    targets: list
    attack_file: Path
    threads: int        = 8
    parse_file: str     = ''
    output_file: str    = ''
    #output_format: str  = 'txt'
    http_methods: list  = field(default_factory = lambda: ['GET'])
    http_headers: MutableMapping[str, str]  = field(default_factory = lambda: {})
    req_proxies: MutableMapping[str, str]   = field(default_factory = lambda: {})
    req_timeout: int    = 8
    color_enabled: bool = True
    make_config: bool   = False
    reset_config: bool  = False
    ignore_acac: bool   = False
    max_rps: int        = 100

def parse_header_args(raw_headers: List[str]) -> Optional[MutableMapping[str, str]]:
    '''
    Parse the headers that are passed in the form:
    ['Host: test', 'User-Agent': 'Something']

    Args:
        raw_headers (List[str]): List of raw header args

    Returns:
        MutableMapping[str, str] | None: Resulting header dictionary or None in case of error
    '''

    headers = {}

    for raw in raw_headers:
        if ':' not in raw:
            error('Invalid header supplied!')
            return None
        
        key, val = raw.strip().split(':', 1)
        
        key = key.replace(' ', '')
        val = val.replace(' ', '')

        headers[key] = val

    return headers

def parse_proxy_args(raw_proxies: List[str]) -> Optional[MutableMapping[str, str]]:
    '''
    Parse the proxies that are passed in the form:
    ['http=socks5://127.0.0.1:9050', 'https=https://someproxy:443']
    
    Args:
        raw_proxies (List[str]): List of raw proxy arguments

    Returns:
        MutableMapping[str, str] | None: Resulting proxy dictionary or None if an error occurs
    '''

    proxies = {}
    
    # im too lazy to do validation

    for raw in raw_proxies:
        if '=' not in raw:
            error('Invalid proxy arg supplied')
            return None

        proto, proxy = raw.split('=', 1)
        proxies[proto] = proxy

    return proxies

def parse_arguments(default_arguments: ArgumentDefaults) -> Namespace:
    '''
    Use argparse to get the parameters from argv 
    * Does no checks

    Returns:
        Namespace: The resulting argparse namespace
    '''

    parser = ArgumentParser(description = 'OverReacher - A convenient CORS scanner tool')

    parser.add_argument('-u', '--urls',   type = str, help = 'Comma separated list of targets')
    parser.add_argument('-i', '--inputs', type = str, help = 'File with a list of targets')
    
    parser.add_argument('--parse',  type = str, 
        help = 'Parse a result file, instead of scanning', default = ''
    )

    parser.add_argument('-o', '--output', type = str, 
        default = default_arguments.output_file,
        help = 'Path to an output file'
    ) 
    
    parser.add_argument('-m', '--methods', type = str, default = default_arguments.http_methods,
        help = f'Comma seperated http methods to use (DEFAULT={default_arguments.http_methods})'
    )

    parser.add_argument('-H', '--header', type = str, action = 'append',
        help = 'Header to be added to requests (can be used multiple times)'
    )
    
    parser.add_argument('-p', '--proxy', type = str, action = 'append',
        help = 'Proxies to be added to requests (multiple) (FMT: https=socks5://user:pass@host:port)'
    )

    parser.add_argument('-t', '--threads', type = int, default = default_arguments.threads,
        help = f'Number of threads to use (DEFAULT={default_arguments.threads})'
    )
    
    parser.add_argument('-T', '--timeout', type = int, default = default_arguments.req_timeout,
        help = f'Set the timeout limit for the requests (DEFAULT={default_arguments.req_timeout})'
    )

    parser.add_argument('-r', '--rate',    type = int, default = default_arguments.rate_limit,
        help = f'Rate of max requests per second (DEFAULT={default_arguments.rate_limit})'
    )

    parser.add_argument('--no-color',      action = 'store_true',
        help = 'Disable color (the NO_COLOR env variable works too)'
    )
    
    parser.add_argument('--make-config', action = 'store_true',
        help = 'Make a .overreacher config directory here. If it already exists, the tool will use the existing one from now on'
    )

    parser.add_argument('--reset-config', action = 'store_true',
        help = 'Reset to the default configuration directory'
    )

    parser.add_argument('-A', '--ignore-acac', action = 'store_true',
        help = 'Enable tracking of where ACAC is set to false'
    )

    args = parser.parse_args()

    return args

def format_arguments(raw_args: Namespace, config: Configuration) -> Optional[ScanArguments]:
    '''
    Format the arguments read from argparse into the proper format
    
    Args:
        raw_args (Namespace): The resulting namespace after parsing from argparse
    Returns:
        ScanArguments | None: Formatted args, or none if an error occured
    '''
    
    # ==== HANDLE THE URLS ====

    urls: List[str] = []

    if raw_args.urls is None and raw_args.inputs is None:
        if not sys.platform.startswith('win'):
            urls = read_urls_stdin()
    elif raw_args.urls is not None:
        urls = filter_urls(raw_args.urls.split(',')) 
    elif raw_args.inputs is not None:
        urls = read_urls_file(raw_args.inputs)

    
    if len(urls) == 0 and not len(raw_args.parse) > 0:
        error('No targets, exitting')
        return None
    
    if len(raw_args.parse) > 0 and not is_file(raw_args.parse):
        error('Supplied previous scan output does not exist!')
        return None

    good(f'Loaded [red]{len(urls)}[/red] targets.')
 
    # ==== HANDLE OTHER PARAMS ====
    
    parsed_headers = parse_header_args(raw_args.header if raw_args.header is not None else [])
    #print(parsed_headers)

    if parsed_headers is None: return None
    
    methods = raw_args.methods.upper().split(',')
    
    if not set(methods) < set(['GET', 'POST', 'OPTIONS', 'HEAD', 'PUT', 'DELETE', 'CONNECT', 'PATCH', 'TRACE']):
        error('Invalid methods selected!')
        return None

    parsed_proxies = parse_proxy_args(raw_args.proxy if raw_args.proxy is not None else [])
    
    if parsed_proxies is None: return None

    return ScanArguments(
        targets = urls,
        attack_file = config.default_args.attacks_file,
        threads = raw_args.threads,
        output_file = raw_args.output,
        parse_file  = raw_args.parse,
        #output_format = raw_args.format,
        http_methods = methods,
        http_headers = parsed_headers,
        req_proxies  = parsed_proxies,
        req_timeout  = raw_args.timeout,
        color_enabled = not (raw_args.no_color or config.default_args.no_color),
        make_config  = raw_args.make_config,
        reset_config = raw_args.reset_config,
        ignore_acac   = (raw_args.ignore_acac or config.default_args.ignore_acac), 
        max_rps = raw_args.rate
    )

def get_arguments(config: Configuration) -> Optional[ScanArguments]:
    '''
    Get, verify and format the commandline arguments into the ScanArguments dataclass

    Returns:
        ScanArguments | None: Parsed args or none, if an error occurs
    '''

    args = parse_arguments(config.default_args)

    return format_arguments(args, config)
