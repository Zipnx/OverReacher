
import json
from core.arguments import ScanArguments
from core.attacks import AttackMethod, AttackResult, Target, execute_attack, execute_attacks, process_attacks
from core.visuals import good,info,error,warn,console

from typing import List, MutableMapping
from dataclasses import dataclass, field

from concurrent.futures import ThreadPoolExecutor, Future, as_completed

from rich.progress import Progress, TaskID, BarColumn, TimeRemainingColumn

from time import sleep

@dataclass(init = True)
class WorkerAssignment:
    target_url: str
    http_method: str

    additional_headers: dict = field(default_factory=dict)

def worker(assign: WorkerAssignment, progress: Progress, task: TaskID) -> List[AttackResult]:
    
    # The from_url should theoretically never error since the url validity is check before in
    # the reading of the urls
    
    target = Target.from_url(assign.target_url)

    if target is None:
        error(f'Target {assign.target_url} is not a url?')
        return []

    results = execute_attacks(target, assign.http_method, additional_headers = assign.additional_headers)

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

    for target in args.targets:
        for method in args.http_methods:
            '''
            for attack in attacks:

                assignments.append(WorkerAssignment(
                    target_url = target, http_method = method, exploit = attack, additional_headers = {} # TODO: Additional headers
                ))
            '''
            assignments.append(WorkerAssignment(
                target_url = target,
                http_method = method,
                additional_headers = args.http_headers
            ))
    
    info(f'Executing {len(assignments)} attacks for {len(args.targets)} targets.')

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

        task = prog.add_task("[cyan]Running attacks...", total = len(assignments))

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

    return format_scan_result(results) 


def format_scan_result(results: List[AttackResult]) -> dict:
    '''
    Take the list of all the scan results and parse them into something more easily readable

    Args:
        results (List[AttackResult]): List of AttackResult objects from the scan

    Returns:
        dict: JSON Result data
    '''

    # First parse it into a dict of target -> []results
    return {} # TODO: Fix later
    target_results: MutableMapping = {}

    for res in results:
        
        if res.exploitation == ExploitStatus.NON_EXPLOITABLE: continue
        
        if res.url not in target_results:
            target_results[res.url] = []
        

        target_results[res.url].append({
            'attack': res.attack.name,
            'method': res.method,
            'exploitable': res.exploitation,
            'payload': res.payload,
            'result': res.result,
            'allow_origin': res.allow_origin,
            'allow_creds': res.allow_credentials
        })
    
    # Cluster the same attack type with different http methods

    result_dict = {}
    return target_results

