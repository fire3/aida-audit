import argparse

def setup_parser(subparsers):
    parser = subparsers.add_parser('binary', help='Query binary metadata')
    
    group = parser.add_argument_group('Required Arguments')
    group.add_argument('binary_name', type=str, help='Name of the binary to query (e.g., target.bin)')
    
    parser.set_defaults(func=handle)

def handle(args, ctx, formatter):
    project_store = ctx.get('project_store')
    if not project_store:
        formatter.format_error("Project store not initialized")
        return
        
    try:
        binary = project_store.get_binary(args.binary_name)
        if not binary:
            formatter.format_error(f"Binary not found: {args.binary_name}")
            return
            
        metadata = binary.get_extended_metadata()
        formatter.format_output(metadata, entity_type="binary", list_view=False)
            
    except Exception as e:
        formatter.format_error(str(e))