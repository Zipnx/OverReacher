
from typing import List
from dataclasses import dataclass

import urllib3
from urllib.parse import urlparse

import json, requests

from .utilities import is_file, validate_attacks_json
from .visuals import good,info,warn,error

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

attack_config_schema = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "request": {
                "type": "object",
                "properties": {
                    "set-origin": {"type": "string"},
                    "append-root": {"type": "string"},
                    "preppend-root": {"type": "string"},
                    "sdomain-separator": {"type": "string"},
                } 
            },
            "response": {
                "type": "object",
                "properties": {
                    "ACAO_WILDCARD": {"type": "string"},
                    "ACAO_NULL": {"type": "string"},
                    "3RD_PARTY": {"type": "string"},
                    "ACAO_EQUAL_ORIGIN": {"type": "string"},
                    "ACAO_EQUAL_OTHER": {"type": "string"}
                }
            }
        },
        "required": ["name", "request", "response"]
    }
}

result_messages = {
    '3RD_PARTY': "A 3rd-Party host is in the ACAO header",
    'NULL_ACAO': "The resulting ACAO header is \"null\"",
    'ALL_WILDCARD': 'The resulting ACAO header is *',
    'ARBITRARY_DATA': 'Arbitrary data is reflected in the ACAO header',
    'ALL_REFLECTED': 'The Origin payload is reflected on the header'
}

class RequestAction:
    def __init__(self, action_json: dict) -> None:

        self.set_origin:        str | None = None
        self.append_root:       str | None = None
        self.preppend_root:     str | None = None
        self.sdomain_separator: str | None = None

        self.parse_options(action_json)

    def parse_options(self, opts: dict) -> None:

        if 'set-origin' in opts:        self.set_origin = opts['set-origin']
        if 'append-root' in opts:       self.append_root = opts['append-root']
        if 'preppend-root' in opts:     self.preppend_root = opts['preppend-root']
        if 'sdomain-separator' in opts: self.sdomain_separator = opts['sdomain-separator']
    
    def is_passive(self) -> bool:
        return self.set_origin is None and self.append_root is None and self.preppend_root is None and self.sdomain_separator is None


@dataclass(init = True)
class Attack:
    name: str

    request_action: RequestAction
    
    @staticmethod
    def from_json(raw_data: dict) -> 'Attack':
        
        req_action: RequestAction  = RequestAction(raw_data['request'])

        return Attack(
            name = raw_data['name'],
            request_action = req_action,
        )

@dataclass(init = True)
class AttackResult:
    url: str
    payload: str
    method: str
    
    attack: Attack
    vulnerable: bool

    allow_origin: str
    allow_credentials: bool
    messages: List[str]


def load_attacks(filepath: str) -> List[Attack]:
    
    info('Loading attack information...')

    if not is_file(filepath):
        error(f'Invalid attacks file: {filepath}')
        return []

    with open(filepath, 'r') as f:
        data = json.load(f)

    if not validate_attacks_json(data, attack_config_schema):
        error('Unable to load attacks')
        return []
    
    attacks: List[Attack] = []

    for i, attack_json in enumerate(data):
        attack = Attack.from_json(attack_json)

        if len(attack.name) == 0:
            error('Unable to load attack #{i}')
            return []
    
        attacks.append(attack)
    
    return attacks

def form_attack_origin(options: RequestAction, target: str) -> str:
    
    if options.is_passive(): return 'no-origin'

    parsed_target = urlparse(target)

    if options.set_origin is None:
        root = parsed_target.netloc
    else:
        root = urlparse(options.set_origin).netloc # This can error fatally

    if options.append_root is not None:
        root += options.append_root

    if options.preppend_root is not None:
        root = options.preppend_root + root

    if options.sdomain_separator is not None:
        dots = root.count('.')
        
        root = root.replace('.', options.sdomain_separator, dots - 1)
    
    return f'{parsed_target.scheme}://{root}'

def form_attack_result_messages(target: str, payload: str, allowOrigin: str, allowCreds: bool) -> List[str]:
    
    if payload == 'no-origin':
        if allowOrigin == '*':
            return [] # Not exploitable
        
        root = urlparse(payload).netloc

    return []

def execute_attack(
    attack: Attack, 
    target: str, 
    method: str, 
    added_headers: dict = {}
) -> AttackResult:
    
    payload = form_attack_origin(attack.request_action, target) 

    res = AttackResult(
        url = target, payload = payload,
        method = method, attack = attack, vulnerable = False, 

        allow_origin = '',
        allow_credentials = False,
        messages = []
    )
    

    req_headers = {}

    if not attack.request_action.is_passive():
        req_headers['Origin'] = payload

    try:
        r = requests.request(method, target, headers = req_headers, verify = False)
    except requests.exceptions.TooManyRedirects:
        error(f'Target {target} skipped due to redirects')
        return res

    except requests.exceptions.Timeout or requests.exceptions.ConnectionError:
        return res

    except requests.exceptions.RequestException as e:
        error(f'Error while attacking {target}: {e}')
        return res
    
    acao = r.headers.get('Access-Control-Allow-Origin')
    acac = r.headers.get('Access-Control-Allow-Credentials')
    
    if not acac: 
        acac = False
    else:
        acac = 'true' in acac

    if not acao: return res # Not vulnerable
    
    res.messages = form_attack_result_messages(target, payload, acao, acac) 
    res.vulnerable = len(res.messages) > 0

    return res





