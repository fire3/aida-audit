import argparse

def setup_parser(subparsers):
    parser = subparsers.add_parser('audit', help='Query audit database (plans, tasks, findings)')
    
    required_group = parser.add_argument_group('Required Arguments')
    required_group.add_argument('--type', '-t', choices=['plan', 'task', 'finding'], required=True, help='Entity type to query')
    
    search_group = parser.add_argument_group('Search Criteria')
    search_group.add_argument('--id', type=str, help='Entity ID (if omitted, lists all)')
    
    parser.set_defaults(func=handle)

def handle(args, ctx, formatter):
    audit_db = ctx.get('audit_db')
    if not audit_db:
        formatter.format_error("Audit database not initialized")
        return
        
    try:
        if args.type == 'plan':
            if args.id:
                plan = audit_db.get_plan(args.id)
                if plan:
                    formatter.format_output(plan, entity_type="plan", list_view=False)
                else:
                    formatter.format_error(f"Plan not found: {args.id}")
            else:
                plans = audit_db.get_plans()
                formatter.format_output(plans, entity_type="plan", list_view=True)
                
        elif args.type == 'task':
            if args.id:
                task = audit_db.get_task(args.id)
                if task:
                    formatter.format_output(task, entity_type="task", list_view=False)
                else:
                    formatter.format_error(f"Task not found: {args.id}")
            else:
                tasks = audit_db.get_tasks()
                formatter.format_output(tasks, entity_type="task", list_view=True)
                
        elif args.type == 'finding':
            findings = audit_db.get_findings()
            if args.id:
                finding = next((f for f in findings if str(f['id']) == args.id), None)
                if finding:
                    formatter.format_output(finding, entity_type="finding", list_view=False)
                else:
                    formatter.format_error(f"Finding not found: {args.id}")
            else:
                formatter.format_output(findings, entity_type="finding", list_view=True)
                
    except Exception as e:
        formatter.format_error(str(e))