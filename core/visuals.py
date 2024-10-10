from dataclasses import dataclass
from rich.console import Console

import time

console = Console()

def setup_console(no_color: bool):
    global console

    if no_color:
        console = Console(color_system = None)
    else:
        console = Console()

def display_banner(version: str) -> None:
    banner = ''' _____               ______                _               
|  _  |              | ___ \\              | |              
| | | |_   _____ _ __| |_/ /___  __ _  ___| |__   ___ _ __ 
| | | \\ \\ / / _ \\ '__|    // _ \\/ _` |/ __| '_ \\ / _ \\ '__|
\\ \\_/ /\\ V /  __/ |  | |\\ \\  __/ (_| | (__| | | |  __/ |   
 \\___/  \\_/ \\___|_|  \\_| \\_\\___|\\__,_|\\___|_| |_|\\___|_|   
                                                          '''

    print(banner)
    console.print(f'\tBy [red]Zipnx[/red] - Version: [green]{version}[/green]\n')

def info(msg: str) -> None:
    console.print(f'[cyan][INFO][/cyan] {msg}')

def good(msg: str) -> None:
    console.print(f'[green][GOOD][/green] {msg}')

def error(msg: str) -> None:
    console.print(f'[red][ERROR][/red] {msg}')

def warn(msg: str) -> None:
    console.print(f'[yellow][WARN][/yellow] {msg}')

def display_scan_results(scan_output: dict) -> None:
    
    scan_info = scan_output['scan_info']
    scan_res  = scan_output['scan_res']

    for target in scan_res:

        target_res = scan_res[target]

        console.print(f'''\n[red][Report][/red] ======= {target} =======''')
        
        for result in target_res:

            console.print(f'\t [cyan]{result["http_method"]}[/cyan] {result["attack_name"]} -> [green]{result["response_code"]} [{result["response_time"]*1000:.2f} ms][/green]')
            console.print(f'\t Result: {result["attack_result"]}')
            console.print(f'\t Payload: {result["used_payload"]}')
            console.print(f'\t Allow Origin: {result["allow_origin"]}')
            
            acac = result['allow_creds']

            console.print(f'\t Allow Credentials: [{"green" if acac else "red"}]{acac}[{"/green" if acac else "/red"}]\n')
    
    console.print()
    info('======= Scan Details =======')
    good(f'\t- Duration: {scan_info["duration"]:.2f} seconds.')
    good(f'\t- Total Targets: {scan_info["target_count"]}')
    good(f'\t- Scan Time: {time.ctime(scan_info["timestamp"])}\n')
    
