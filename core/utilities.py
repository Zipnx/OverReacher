
from typing import List
import sys, re, select

from os.path import exists as fileExists
from os.path import isdir  as isDirectory
import os
from urllib.parse import urlparse

from urllib3.exceptions import URLSchemeUnknown

from .visuals import good,info,warn,error

URL_REGEX = re.compile(r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)')

def is_url(url: str) -> bool:
    '''
    Check whether a given string is a valid url

    Args:
        url (str): String to Check

    Returns:
        bool: Whether it is a url
    '''
    return URL_REGEX.match(url) is not None

def filter_urls(urls: List[str]) -> List[str]:
    '''
    Given a list of possible url strings, it will return a list of only the valid urls
    
    Args:
        urls (List[str]): List of possible urls
        
    Returns:
        List[str]: List of confirmed urls
    '''
    return list(filter(lambda url: URL_REGEX.match(url) is not None, urls))

def read_urls_stdin() -> List[str]:
    '''
    Read and filter urls piped from stdin

    Returns:
        List[str]: List of urls read
    '''    

    # In case there is no data to be read
    if not select.select([sys.stdin], [], [], 0.2)[0]:
        return []

    try:
        data = sys.stdin.buffer.readlines()
        lines = [line.decode('utf-8').strip('\n\r') for line in data]
    except BaseException as e:
        error(f'Error reading targets from stdin: {e}')
        return []

    return filter_urls(lines)

def read_urls_file(path: str) -> List[str]:
    '''
    Read and filter urls from a given file
    
    Args:
        path (str): Filepath of file to read from

    Returns:
        List[str]: List of confirmed urls
    '''
    
    if not is_file(path):
        error('Not a valid input file!')
        return []
    
    with open(path, 'r') as f:
        return filter_urls([line.strip('\n\r') for line in f])

def is_file(filepath: str) -> bool:
    '''
    Check if a string is a valid filepah
    
    Args:
        filepath (str): Filepath to Check

    Returns:
        bool: Validity
    '''

    return fileExists(filepath) and not isDirectory(filepath)

def get_host(url: str) -> str:

    if URL_REGEX.match(url) is None: return url

    return urlparse(url).netloc

