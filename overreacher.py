
import core
from core.arguments import ScanArguments,get_arguments
from core.visuals import display_banner

from core.execute import scan 

def main():
    display_banner(core.__version__)

    args = get_arguments()

    if args is None:
        return

    scan(args)

if __name__ == '__main__':
    main()
