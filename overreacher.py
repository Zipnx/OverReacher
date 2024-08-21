
from core.arguments import ScanArguments,parse_arguments
from core.execute import scan 

def main():
    args = parse_arguments()

    if args is None:
        return

    scan(args)

if __name__ == '__main__':
    main()
