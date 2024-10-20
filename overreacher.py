
import core

from core.config import Configuration, load_config
from core.arguments import ScanArguments,get_arguments
from core.visuals import reload_no_color, display_banner, display_scan_results, good, error, info

from core.execute import scan 
import json, sys

def main():
    
    config = load_config()
    
    #print(config.default_headers)

    if '--no-color' in sys.argv or config.default_args.no_color:
        reload_no_color()

    display_banner(core.__version__)
    
    args = get_arguments(config)
 
    if args is None:
        return   
    
    if len(args.parse_file) > 0:
        info('Parsing previous attack result...\n')

        with open(args.parse_file, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                error('Error loading previous attack JSON. Invalid')
                return

            display_scan_results(data)
            return


    results = scan(config, args)
    
    if len(results) == 0: return

    display_scan_results(results)
    
    # Handle saving
    if len(args.output_file) > 0:
        
        good(f'Saving output to {args.output_file}')

        with open(args.output_file, 'w') as f:
            json.dump(results, f, indent = 4)
            f.write('\n')


if __name__ == '__main__':
    main()
