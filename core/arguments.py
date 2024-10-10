
from typing import List

import sys
from dataclasses import dataclass, field
from argparse import ArgumentParser, Namespace

from core.utilities import read_urls_file

from .utilities import filter_urls, read_urls_stdin

from .visuals import info,good,error,warn

@dataclass(init = True)
class ScanArguments:
    targets: list
    threads: int        = 8
    output_file: str    = ''
    #output_format: str  = 'txt'
    http_methods: list  = field(default_factory = lambda: ['GET', 'POST'])
    http_headers: dict  = field(default_factory = lambda: {})
    color_enabled: bool = True
    max_rps: int        = 100

def parse_arguments() -> Namespace:
    '''
    Use argparse to get the parameters from argv 
    * Does no checks

    Returns:
        Namespace: The resulting argparse namespace
    '''

    parser = ArgumentParser(description = 'OverReacher - A convenient CORS scanner tool')

    parser.add_argument('-u', '--urls',   type = str, help = 'Comma separated list of targets')
    parser.add_argument('-i', '--inputs', type = str, help = 'File with a list of targets')
    
    parser.add_argument('-o', '--output', type = str, 
        default = '',
        help = 'Path to an output file'
    )
    
    # TODO: Implement at some point
    #parser.add_argument('-f', '--format', 
    #    choices = ['txt', 'json'], 
    #    default = 'txt',
    #    help = 'Save format (DEFAULT=txt)'
    #)
    
    parser.add_argument('-m', '--methods', type = str, default = 'GET,POST',
        help = 'Comma seperated http methods to use (DEFAULT=GET,POST)'
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

def format_arguments(raw_args: Namespace) -> ScanArguments | None:
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
        urls = read_urls_stdin()
    elif raw_args.urls is not None:
        urls = filter_urls(raw_args.urls.split(',')) 
    elif raw_args.inputs is not None:
        urls = read_urls_file(raw_args.inputs)


    if len(urls) == 0:
        error('No targets, exitting')
        return None

    good(f'Loaded [red]{len(urls)}[/red] targets.')
 
    # ==== HANDLE OTHER PARAMS ====
    

    return ScanArguments(
        targets = urls,
        threads = raw_args.threads,
        output_file = raw_args.output,
        #output_format = raw_args.format,
        http_methods = raw_args.methods.split(','), # TODO: Validate methods
        http_headers = {}, # TODO: Parse the headers into dict form
        color_enabled = not raw_args.no_color, # TODO: No color ENV variable
        max_rps = raw_args.rate
    )

def get_arguments() -> ScanArguments | None:
    '''
    Get, verify and format the commandline arguments into the ScanArguments dataclass

    Returns:
        ScanArguments | None: Parsed args or none, if an error occurs
    '''

    args = parse_arguments()

    return format_arguments(args)
