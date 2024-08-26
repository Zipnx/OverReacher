from rich.console import Console

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
