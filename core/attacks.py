
from collections.abc import MutableMapping
from enum import IntEnum
from typing import List, Tuple, Optional, Self
from dataclasses import dataclass

import urllib3
from urllib.parse import urlparse

from copy import deepcopy
import requests

from core.utilities import is_url
from core.visuals import good,info,warn,error

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass(init = True)
class AttackMethod:
    name: str

    success_msg: str
    is_passive: bool = False

    process: dict | None = None

    def set_proc(self, process_json: dict | None) -> Self:
        self.process = process_json
        return self

@dataclass(init = True)
class Target:
    _scheme: str
    root: str
    _path: str
    
    @staticmethod
    def from_url(url: str) -> Optional['Target']:
        if not is_url(url): return None

        parse_res = urlparse(url)

        return Target(
            _scheme = parse_res.scheme,
            root = parse_res.netloc,
            _path = parse_res.path
        )

    def to_url(self):
        return f'{self._scheme}://{self.root}{self._path if len(self._path) > 0 else ""}'


DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip',
    'DNT': '1',
    'Connection': 'close',
}

# This defines the attacks, will make it more customizable later on
# The order of this list indicates in what order the requests will be sent to the target
EXPLOITS: List[AttackMethod] = [

    # This will do a passive check to see what the host returns
    AttackMethod(
        name            = 'Passive Tests',
        success_msg     = '', # On this, the wild card / third party msg is set during the test
        is_passive      = True
    ).set_proc(None),

    AttackMethod(
        name            = 'Null origin',
        success_msg     = 'Target accepts null origin',
        is_passive = True
    ).set_proc({
        'set-null': True
    }),
    
    AttackMethod(
        name            = 'Arbitrary data reflection',
        success_msg     = 'Target reflects on the ACAO header any data sent in the origin header'
    ).set_proc({
        'set-origin': 'random_data_lel',
    }),

    # Different url test case
    AttackMethod(
        name            = 'Arbitrary url reflection',
        success_msg     = 'Target allows requests from ANY domain',

    ).set_proc({
        'set-origin-url': 'example.com'
    }),

    # The post domain wildcard options
    AttackMethod(
        name            = 'Post domain wildcard',
        success_msg     = 'Target allows requests from any domain with it as a prefix',
    ).set_proc({
        'append-root': 'example.com'
    }),

    AttackMethod(
        name            = 'Post domain wildcard (subdomain)',
        success_msg     = 'Target allows requests from any domain with it as a subdomain',
    ).set_proc({
        'append-root': '.example.com'
    }),

    AttackMethod(
        name            = 'Pre domain wildcard',
        success_msg     = 'Target allows requests from any domain with it as a postfix',
        is_passive      = True # This is hacky but i want the other tests to be executes as well,
        #                        as this is not that useful on some case
    ).set_proc({
        'preppend-root': 'evil'
    }),

    #
    # APPEND BYPASS CHECKS 
    #

    AttackMethod(
        name            = 'Underscore append bypass',
        success_msg     = 'Can bypass checking by appending an underscore (_)',
    ).set_proc({
        'append-root': '_.example.com'
    }),

    AttackMethod(
        name            = 'Backtick append bypass',
        success_msg     = 'Can bypass checking by appending a backtick (`)',
    ).set_proc({
        'append-root': '%60.example.com'
    }),

    AttackMethod(
        name            = 'Backtick append bypass, electric boogaloo',
        success_msg     = 'Can bypass checking by appending an underscore',
    ).set_proc({
        'append-root': '%60example.com'
    }),

    #
    # BROKEN REGEX TEST
    #

    AttackMethod(
        name            = 'Regex unescaped dot',
        success_msg     = 'Due to broken regex, the host interpretes a dot as any',
    ).set_proc({
        # Here we need to replace a subdomain's dot separator, so it's functionality will be a bit funky
        'replace-sdomain-sep': 'x'
    }),


]

@dataclass(init = True)
class AttackResult:
    target: Target
    method: str
    elapsed: float
    status_code: int
    
    payload: str | None
    allow_origin: str
    allow_creds: bool

    exploit : AttackMethod
    msg: str = ''

# Url & method combinations in this list will be ignored further in the scan
IGNORE_LIST: List[Tuple[str, str]] = []

# Urls in this list will be passed (deemed offline / blocked)
SKIP_LIST: List[str] = []

# TODO: Make the level and prev settings work as intended
def process_attacks():
    return EXPLOITS

def form_payload(target: Target, exploit: AttackMethod) -> str | None:
    
    if exploit.process is None: return
    proc = exploit.process

    for option in proc:

        if option == 'set-origin':
            # This forces a return
            return proc[option]

        elif option == 'set-origin-url': 
            target.root = proc[option]

        elif option == 'set-null': 
            # This also forces a return
            return 'null'

        elif option == 'append-root': 
            target.root += proc[option]

        elif option == 'preppend-root':
            target.root = proc[option] + target.root

        elif option == 'replace-sdomain-sep':
            sep_count = target.root.count('.')
            target.root = target.root.replace('.', proc[option], sep_count - 1)
    
    return target.to_url()

def execute_attacks(target: Target, method: str, additional_headers: MutableMapping[str, str] = {}) -> List[AttackResult]:
    
    results: List[AttackResult] = []

    for exploit in EXPLOITS:
        res = execute_attack(target, method, exploit, additional_headers)

        if res is None: continue
    
        res.exploit = exploit

        if exploit.is_passive:
            if len(exploit.success_msg) == 0: continue

        results.append(res)

        if not exploit.is_passive:
            break

    return results


def execute_attack(target: Target, method: str, exploit: AttackMethod, additional_headers: MutableMapping[str, str] = {}) -> Optional[AttackResult]:
    
    headers = {**DEFAULT_HEADERS, **additional_headers}
    
    target_url = target.to_url()

    # This is theoretically thread safe, idc
    if target_url in SKIP_LIST: return None
    if (target_url, method) in IGNORE_LIST: return None
    
    payload = form_payload(deepcopy(target), exploit)
    
    if payload is not None:
        headers['Origin'] = payload 
    
    try:
        r = requests.request(
            method, target.to_url(), headers = headers, verify = False, timeout = 10
        )
    except requests.exceptions.TooManyRedirects:
        error(f'Target {target_url} skipped due to redirects')
        
        SKIP_LIST.append(target_url)
        return

    except requests.exceptions.Timeout or requests.exceptions.ConnectionError:
        error(f'Connection error to {target_url}')
        SKIP_LIST.append(target_url)
        return

    except requests.exceptions.RequestException as e:
        #error(f'Error while attacking {target_url}: {str(e)}')
        SKIP_LIST.append(target_url)
        return
    
    if target_url in SKIP_LIST or (target_url, method) in IGNORE_LIST: return None

    acao = r.headers.get('Access-Control-Allow-Origin')
    acac = r.headers.get('Access-Control-Allow-Credentials')
    
    #print(acao, acac)

    if not acac:
        acac = False
    else:
        acac = 'true' in str(acac).lower()
     
    result_root = urlparse(acao).netloc

    if exploit.process is None and acao is not None:
        if acao == '*':
            exploit.success_msg = 'Target has wildcard ACAO'

        elif result_root != target.root:
            exploit.success_msg = 'Target has a 3rd Party set as allowed'
    
    vulnerable: bool = acao is not None
    vulnerable &= ( (acao == payload) or payload is None )

    if not vulnerable:
        return

    result: AttackResult = AttackResult(
        target = target,
        method = method,
        elapsed = r.elapsed.total_seconds(),
        status_code = r.status_code,
        
        payload = payload,
        allow_origin = acao,
        allow_creds = acac,
        exploit = exploit,
        msg = exploit.success_msg
    )

    return result
