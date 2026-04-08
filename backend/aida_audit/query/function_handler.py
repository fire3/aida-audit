import argparse

def setup_parser(subparsers):
    parser = subparsers.add_parser('function', help='Query function metadata, pseudocode, and calls')
    
    required_group = parser.add_argument_group('Required Arguments')
    required_group.add_argument('--binary', '-b', required=True, help='Target binary name')
    
    search_group = parser.add_mutually_exclusive_group()
    search_group.add_argument('--name', '-n', help='Search by function name')
    search_group.add_argument('--address', '-a', help='Search by function address (hex)')
    
    ext_group = parser.add_argument_group('Extension Flags')
    ext_group.add_argument('--pseudocode', action='store_true', help='Include function pseudocode')
    ext_group.add_argument('--calls', action='store_true', help='Include callers and callees')
    
    list_group = parser.add_argument_group('List Options')
    list_group.add_argument('--limit', type=int, default=50, help='Maximum number of functions to return')
    list_group.add_argument('--offset', type=int, default=0, help='Pagination offset')
    
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
            # Search by name
            funcs = binary.get_function_by_name(args.name)
            if not funcs:
                formatter.format_error(f"Function not found: {args.name}")
                return
            func = funcs[0] if isinstance(funcs, list) else funcs
            _enrich_and_output(func, binary, args, formatter)
            
        elif args.address:
            # Search by address
            func = binary.get_function_by_address(args.address)
            if not func:
                formatter.format_error(f"Function not found at address: {args.address}")
                return
            _enrich_and_output(func, binary, args, formatter)
            
        else:
            # List functions
            funcs = binary.list_functions(offset=args.offset, limit=args.limit)
            formatter.format_output(funcs, entity_type="function", list_view=True)
            
    except Exception as e:
        formatter.format_error(str(e))

def _enrich_and_output(func, binary, args, formatter):
    result = dict(func)
    address = func.get("start_address")
    
    if args.pseudocode and address:
        pseudo = binary.get_function_pseudocode_by_address(address)
        if pseudo:
            result["pseudocode"] = pseudo.get("pseudocode", "")
            
    if args.calls and address:
        callers = binary.get_function_callers(address)
        callees = binary.get_function_callees(address)
        
        # handle pagination format
        if callers and "results" in callers: callers = callers["results"]
        if callees and "results" in callees: callees = callees["results"]
            
        result["callers"] = [c.get("caller_name", c.get("caller_address", "")) for c in callers] if callers else []
        result["callees"] = [c.get("callee_name", c.get("callee_address", "")) for c in callees] if callees else []
        
    formatter.format_output(result, entity_type="function", list_view=False)