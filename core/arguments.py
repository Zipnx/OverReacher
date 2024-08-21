
from dataclasses import dataclass, field

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

def parse_arguments() -> ScanArguments | None: 
    return ScanArguments(['127.0.0.1'])
