
import core
from core.arguments import ScanArguments,get_arguments
from core.visuals import display_banner, display_scan_results

from core.execute import scan 
import json

def main():
    #'''
    display_banner(core.__version__)

    args = get_arguments()

    if args is None:
        return

    results = scan(args)
    
    print(results)

    with open('req.tmp', 'w') as f:
        json.dump(results, f, indent = 4)
    #'''
    
    return

    with open('req.tmp', 'r') as f:
        data = json.load(f)

    display_scan_results(data)


if __name__ == '__main__':
    main()
