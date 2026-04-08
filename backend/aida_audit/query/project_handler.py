import argparse

def setup_parser(subparsers):
    parser = subparsers.add_parser('project', help='Query project overview and binaries')
    
    group = parser.add_argument_group('Query Options')
    group.add_argument('--detail', action='store_true', help='Include detailed metadata for binaries')
    group.add_argument('--limit', type=int, default=50, help='Maximum number of binaries to return')
    group.add_argument('--offset', type=int, default=0, help='Pagination offset')
    
    parser.set_defaults(func=handle)

def handle(args, ctx, formatter):
    project_store = ctx.get('project_store')
    if not project_store:
        formatter.format_error("Project store not initialized")
        return
        
    try:
        overview = project_store.get_overview()
        binaries = project_store.get_project_binaries(offset=args.offset, limit=args.limit, detail=args.detail)
        
        result = {
            "overview": overview,
            "binaries": binaries
        }
        
        # Simplified display for text/markdown
        if formatter.format_type != "json":
            # For non-json, we might want to just show binaries if that's the focus,
            # or a summary of overview and list of binaries.
            # Let's format it as a list view of binaries, but maybe with a title.
            formatter.format_output(binaries, entity_type="binary", list_view=True)
        else:
            formatter.format_output(result, entity_type="project", list_view=False)
            
    except Exception as e:
        formatter.format_error(str(e))
