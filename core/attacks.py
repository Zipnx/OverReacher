
from enum import IntEnum
from typing import List, Literal
from dataclasses import dataclass

import urllib3
from urllib.parse import urlparse

import json, requests

from .utilities import get_host, is_file, validate_attacks_json
from .visuals import good,info,warn,error

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ExploitStatus(IntEnum):
    SAFE = 0
    MAYBE = 1
    EXPLOITABLE = 2
    UNKNOWN = 3

class Attack:
    cover_level: int
    url: str
    
    method: Literal['GET', 'POST', 'OPTIONS', 'HEAD', 'TRACE', 'DELETE', 'PUT', 'CONNECT', 'PATCH'] = 'POST'
