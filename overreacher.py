
import core
from core.arguments import ScanArguments,get_arguments
from core.visuals import display_banner, display_scan_results, good, error, info

from core.execute import scan 
import json

def main():
    #'''
    display_banner(core.__version__)

    args = get_arguments()

    if args is None:
        return

    results = None#scan(args)

    #with open('req.tmp', 'w') as f:
    #    json.dump(results, f, indent = 4)

    with open('req.tmp', 'r') as f:
        results = json.load(f)

    display_scan_results(results)
    
    # Handle saving
    if len(args.output_file) > 0:
        
        good(f'Saving output to {args.output_file}')

        with open(args.output_file, 'w') as f:
            json.dump(results, f, indent = 4)
            f.write('\n')


if __name__ == '__main__':
    main()
