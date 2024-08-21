
from core.arguments import ScanArguments,get_arguments
from core.execute import scan 

def main():
    args = get_arguments()

    if args is None:
        return

    scan(args)

if __name__ == '__main__':
    main()
