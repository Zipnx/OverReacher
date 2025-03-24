
from .version import __version__
from .config import Configuration, load_config, setup_config_dir, default_config_dir
from .arguments import ScanArguments,get_arguments
from .visuals import reload_no_color, display_banner, display_scan_results, good, error, info

from .execute import scan 

from pathlib import Path
import json, sys

def main():
    
    # This is hacky, make it better
    # (this needs to be done before the config loading, incase of invalid config)
    if '--make-config' in sys.argv:
        from os import getcwd

        if setup_config_dir(Path(getcwd())):
            good('New config location setup.')
        else:
            error('Unable to set new configuration location.')

        return
    
    if '--reset-config' in sys.argv:
        info('Resetting configuration...')
        default_config_dir()
        return

    config = load_config()
    
    if config is None:
        error("Error loading configuration!")
        return

    #print(config.default_headers)

    if '--no-color' in sys.argv or config.default_args.no_color:
        reload_no_color()

    display_banner(__version__)
    
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
