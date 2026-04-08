import argparse

def setup_parser(subparsers):
    parser = subparsers.add_parser('symbol', help='Query and resolve symbols')
    
    required_group = parser.add_argument_group('Required Arguments')
    required_group.add_argument('--binary', '-b', required=True, help='Target binary name')
    
    search_group = parser.add_mutually_exclusive_group()
    search_group.add_argument('--name', '-n', help='Resolve symbol by name')
    search_group.add_argument('--address', '-a', help='Resolve symbol by address (hex)')
    
    parser.set_defaults(func=handle)

def handle(args, ctx, formatter):
    project_store = ctx.get('project_store')
    if not project_store:
        formatter.format_error("Project store not initialized")
        return
        
    try:
        binary = project_store.get_binary(args.binary)
        if not binary:
            formatter.format_error(f"Binary not found: {args.binary}")
            return
            
        if args.name:
            # Resolve symbol by name
            addr = binary.resolve_symbol(args.name)
            if not addr:
                formatter.format_error(f"Symbol not found: {args.name}")
                return
            formatter.format_output({"name": args.name, "address": addr}, entity_type="symbol", list_view=False)
            
        elif args.address:
            # Resolve address to symbol
            sym = binary.resolve_address(args.address)
            if not sym:
                formatter.format_error(f"No symbol at address: {args.address}")
                return
            formatter.format_output({"address": args.address, "name": sym}, entity_type="symbol", list_view=False)
            
        else:
            # List symbols
            symbols = binary.list_symbols(limit=50) # default limit
            formatter.format_output(symbols, entity_type="symbol", list_view=True)
            
    except Exception as e:
        formatter.format_error(str(e))