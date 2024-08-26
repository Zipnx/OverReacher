
from .arguments import ScanArguments
from .attacks import Attack, AttackResult, load_attacks, execute_attack
from .visuals import good,info,error,warn,console

from typing import List
from dataclasses import dataclass

from concurrent.futures import ThreadPoolExecutor, Future, as_completed

from rich.progress import Progress, TaskID, BarColumn, TimeRemainingColumn
from rich.console import Console

from time import sleep

@dataclass(init = True)
class WorkerAssignment:
    attack: Attack
    target: str
    method: str
    additional_headers: dict

def worker(assign: WorkerAssignment, progress: Progress, task: TaskID) -> AttackResult:

    result = execute_attack(assign.attack, assign.target, assign.method, assign.additional_headers)

    progress.advance(task)

    if result.vulnerable:
        console.print(f'[green]Status:[/green] {assign.method} {assign.target}')

    return result


def scan(args: ScanArguments) -> None:
    '''
    Execute the scan given the supplied arguments
    '''

    # Setup worker jobs
    
    assignments: List[WorkerAssignment] = []
    attacks: List[Attack] = load_attacks('./attacks/attacks.json')

    for target in args.targets:
        for method in args.http_methods:
            for attack in attacks:

                assignments.append(WorkerAssignment(
                    attack = attack, target = target, method = method, additional_headers = {} # TODO: Additional headers
                ))
    
    info(f'Executing {len(assignments)} attacks.')

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
                    results.append(res)
                except BaseException as e:
                    error(f'[red]Error:[/red] {e}')
                    #raise e

    print(len(results))
