
import json, time
from core.arguments import ScanArguments
from core.attacks import AttackMethod, AttackResult, Target, execute_attacks, process_attacks
from core.visuals import good,info,error,warn,console

from typing import List, MutableMapping
from dataclasses import dataclass, field

from concurrent.futures import ThreadPoolExecutor, Future, as_completed

from rich.progress import Progress, TaskID, BarColumn, TimeRemainingColumn

@dataclass(init = True)
class WorkerAssignment:
    target_url: str
    http_method: str
    time_throttle: float

    additional_headers: MutableMapping[str, str] = field(default_factory=dict)

def worker(assign: WorkerAssignment, progress: Progress, task: TaskID) -> List[AttackResult]:
    
    # The from_url should theoretically never error since the url validity is check before in
    # the reading of the urls
    
    target = Target.from_url(assign.target_url)

    if target is None:
        error(f'Target {assign.target_url} is not a url?')
        return []

    results = execute_attacks(target, assign.http_method, additional_headers = assign.additional_headers, delay = assign.time_throttle)

    progress.advance(task)

    for result in results:
        console.print(f'[red][FOUND][/red] [green]{assign.http_method}[/green] {assign.target_url} ({result.exploit.name})\n\t- {result.msg}')
        '''
        console.print(f'[red][FOUND][/red] \t - Attack: {assign.attack.name}')
        #console.print(f'[red][FOUND][/red] \t - Result: [cyan]{result.result}[/cyan]')
        #console.print(f'[red][FOUND][/red] \t - Details: {result.payload} -> {result.allow_origin}')
        #console.print(f'[red][FOUND][/red] \t - Allow Credentials: [red]{result.allow_credentials}[/red]\n')


        console.print(f\'''[red][FOUND][/red] [green]{assign.method}[/green] {assign.target}
[red][FOUND][/red] \t - Attack: {assign.attack.name}
[red][FOUND][/red] \t - Result: [cyan]{result.result}[/cyan]
[red][FOUND][/red] \t - Details: {result.payload} -> {result.allow_origin}
[red][FOUND][/red] \t - Allow Credentials: [red]{result.allow_credentials}[/red]\n\''')
        '''

    return results


def scan(args: ScanArguments) -> dict:
    '''
    Execute the scan given the supplied arguments
    '''
    
    # Setup worker jobs
    
    assignments: List[WorkerAssignment] = []
    attacks: List[AttackMethod] = process_attacks()
    
    delays = 1 / (args.max_rps / args.threads * len(attacks))

    for target in args.targets:
        for method in args.http_methods:
            assignments.append(WorkerAssignment(
                target_url = target,
                http_method = method,
                time_throttle = delays,
                additional_headers = args.http_headers
            ))
    
    info(f'Using {args.threads} threads.')
    info(f'Executing {len(assignments)} attacks for {len(args.targets)} targets.\n')
    
    t0 = time.time()

    # Execute workers

    results: list = []

    with Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        "{task.completed}/{task.total} Done",
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        console = console,
    ) as prog:

        task = prog.add_task("[cyan][*] Running attacks...", total = len(assignments))

        with ThreadPoolExecutor(max_workers = args.threads) as executor:

            futures: List[Future] = []

            for assignment in assignments:

                futures.append(
                    executor.submit(worker, assignment, prog, task)
                )

            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res is not None:
                        results += res
                except BaseException as e:
                    error(f'[red]Error:[/red] {e}')
                    #raise e
    
    scan_time = time.time() - t0
    info(f'Done after {scan_time:.2f} seconds.')

    return format_scan_result(results, scan_time, len(args.targets)) 


def format_scan_result(results: List[AttackResult], elapsed: float, target_count: int) -> dict:
    '''
    Take the list of all the scan results and parse them into something more easily readable

    Args:
        results (List[AttackResult]): List of AttackResult objects from the scan
        elapsed (float): Scan duration in seconds
        target_count (int): Count of targets scanned

    Returns:
        dict: JSON Result data
    '''

    # First parse it into a dict of target -> []results
    target_results: MutableMapping = {}

    for res in results:
         
        target_url = res.target.to_url()
        
        if target_url not in target_results:
            target_results[target_url] = []

        result_json = {
            'http_method': res.method,
            'response_code': res.status_code,
            'response_time': res.elapsed,
            'attack_name': res.exploit.name,
            'attack_result': res.msg,
            'used_payload': res.payload,
            'allow_origin': res.allow_origin,
            'allow_creds': res.allow_creds
        }
        
        target_results[target_url].append(result_json)

    # Cluster the same attack type with different http methods
    
    output = {
        'scan_info': {
            'duration': elapsed,
            'target_count': target_count,
            'timestamp': int(time.time()) 
        },
        'scan_res': target_results
    }

    return output

