
from collections.abc import MutableMapping
from enum import IntEnum
from typing import List, Tuple, Optional, Self
from dataclasses import dataclass

from os.path import realpath
from pathlib import Path

import urllib3
from urllib.parse import urlparse

from copy import deepcopy
import requests, time, json

from core.utilities import is_file, is_url
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
    
    def to_json(self) -> dict:
        '''
        Serialize the AttackMethod object to json

        Returns:
            dict: Serialized JSON
        '''

        return {
            'name': self.name,
            'success_msg': self.success_msg,
            'is_passive': self.is_passive,
            'process': self.process
        }

    @staticmethod
    def from_json(attack_json: dict) -> Optional['AttackMethod']:
        '''
        Get an AttackMethod object from it's serialized json form
        *** WARNING: No validation is done here

        Args:
            attack_json (dict): Attack in JSON form

        Returns:
            AttackMethod | None: The resulting object or None in case of error

        '''    

        return AttackMethod(
            name = attack_json['name'],
            success_msg = attack_json['success_msg'],
            is_passive = attack_json['is_passive'],
            process = attack_json['process']
        )

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
EXPLOITS: List[AttackMethod] = []
#ATTACK_FILE = Path(__file__).parent.parent.resolve() / 'data/attacks.json' 

def load_attacks(attack_file) -> List[AttackMethod]:
    '''
    Load the attacks from the configured attack file
    *** Note: Also sets the EXPLOITS global var

    Returns:
        List[AttackMethod]: List of attacks
    '''
    global EXPLOITS
    
    attack_file = Path(__file__).parent.parent.resolve() / attack_file

    if not is_file(attack_file):
        error(f'Input attack file "{attack_file}" does not exist!')
        return []

    with open(attack_file, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            error('Attacks JSON invalid contained invalid data!')
            return []

    attacks: List[AttackMethod] = []

    for raw in data:
        attack = AttackMethod.from_json(raw)

        if attack is None:
            error('Invalid attack JSON')
            continue

        attacks.append(attack)
    
    del EXPLOITS
    EXPLOITS = attacks

    return attacks

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

# TODO: Loading attacks from file, again
def process_attacks():
    return EXPLOITS

def form_payload(target: Target, exploit: AttackMethod) -> str | None:
    
    if exploit.process is None: return
    proc = exploit.process

    for option in proc:

        if option == 'set-origin':
            # This forces a return
            return proc[option]
        
        if option == 'preppend-origin':
            return proc[option] + target.to_url()

        if option == 'append-origin':
            return target.to_url() + proc[option]

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

def execute_attacks(
        target: Target, 
        method: str, 
        additional_headers: MutableMapping[str, str] = {}, 
        delay: float = 0., 
        timeout: int = 8, 
        proxies: MutableMapping[str, str] = {},
        ignore_acac: bool = False
    ) -> List[AttackResult]:
    '''
    Execute an attack against a target with all available exploits
    
    Args:
        target (Target): Target to attack
        method (str): HTTP Method to use
        additional_headers (dict): Additional headers to send in the requests
        delay (float): Delay to use between requests in seconds (DEFAULT=0)
    
    Returns:
        List[AttackResult]: Results from the attack
    '''
    
    results: List[AttackResult] = []

    for exploit in EXPLOITS:
        res = execute_attack(target, method, exploit, timeout, additional_headers, proxies, ignore_acac = ignore_acac)
        time.sleep(delay) 

        if res is None: continue
    
        res.exploit = exploit

        if exploit.is_passive:
            if len(exploit.success_msg) == 0: continue

        results.append(res)

        if not exploit.is_passive:
            break

    return results


def execute_attack(
        target: Target, 
        method: str, 
        exploit: AttackMethod, 
        timeout: int, 
        additional_headers: MutableMapping[str, str] = {}, 
        proxies: MutableMapping[str, str] = {},
        ignore_acac: bool = False
    ) -> Optional[AttackResult]:
    
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
            method, target.to_url(), headers = headers, proxies = proxies, verify = False, timeout = timeout
        )
    except requests.exceptions.TooManyRedirects:
        error(f'Target {target_url} skipped due to redirects')
        
        SKIP_LIST.append(target_url)
        return
    
    except requests.exceptions.ProxyError:
        error(f'*** PROXY ERROR ***')
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
    
    if not acac and not ignore_acac: return

    result_root = urlparse(acao).netloc

    if exploit.process is None and acao is not None:
        if acao == '*':
            exploit.success_msg = 'Target has wildcard ACAO'
        
        elif acao == 'null':
            exploit.success_msg = 'Target passively returns a null ACAO'

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
