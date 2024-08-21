
from .arguments import ScanArguments

from typing import List
from dataclasses import dataclass

from concurrent.futures import ThreadPoolExecutor, Future, as_completed

from rich.progress import Progress, TaskID, BarColumn, TimeRemainingColumn
from rich.console import Console

from time import sleep

console = Console()

@dataclass(init = True)
class WorkerAssignment:
    test_type: str
    target: str
    method: str
    additional_headers: dict

def worker(assign: WorkerAssignment, progress: Progress, task: TaskID):

    sleep(1)
    progress.advance(task)

    if '8080' in assign.target:
        console.print(f'[green]Status:[/green] {assign.method} {assign.target}')

    return f'executed'


def scan(args: ScanArguments) -> None:
    '''
    Execute the scan given the supplied arguments
    '''
    
    results: list = []

    with Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        "{task.completed}/{task.total} Done",
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        console = console,
    ) as prog:

        task = prog.add_task("[cyan]Running attacks...", total = len(args.targets))

        with ThreadPoolExecutor(max_workers = args.threads) as executor:

            futures: List[Future] = []

            for target in args.targets:

                assignment: WorkerAssignment = WorkerAssignment('', target, 'GET', {})

                futures.append(
                    executor.submit(worker, assignment, prog, task)
                )

            for future in as_completed(futures):
                try:
                    res = future.result()
                    results.append(res)
                except BaseException as e:
                    console.print(f'[red]Error:[/e] {e}')

    print(len(results))
