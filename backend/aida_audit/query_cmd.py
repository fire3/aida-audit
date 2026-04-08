import sys
import os
import argparse
import logging
from .query import project_handler, binary_handler, function_handler, symbol_handler, audit_handler
from .query.formatter import OutputFormatter
from .project_store import ProjectStore
from .audit_database import AuditDatabase
from .constants import AUDIT_DB_FILENAME

def main():
    parser = argparse.ArgumentParser(
        prog='aida-audit query',
        description='AIDA-AUDIT Query CLI - Query binary analysis and audit data without starting the server.',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''
Examples:
  # Query project overview
  aida-audit query project
  
  # Search function by address with pseudocode and calls
  aida-audit query function -b target.bin -a 0x401000 --pseudocode --calls -f json
  
  # List audit findings in markdown
  aida-audit query audit -t finding -f markdown
'''
    )
    
    # Global options
    parser.add_argument('--project', '-p', default='.', help='Path to the project directory containing .db files')
    parser.add_argument('--format', '-f', choices=['json', 'text', 'markdown'], default='text', help='Output format (default: text)')
    
    subparsers = parser.add_subparsers(title='Subcommands', dest='command', required=True)
    
    # Setup subcommands
    project_handler.setup_parser(subparsers)
    binary_handler.setup_parser(subparsers)
    function_handler.setup_parser(subparsers)
    symbol_handler.setup_parser(subparsers)
    audit_handler.setup_parser(subparsers)
    
    # In case of no arguments, show help and exit
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    
    # Initialize OutputFormatter
    formatter = OutputFormatter(format_type=args.format)
    
    # Initialize Context
    ctx = {}
    project_path = os.path.abspath(args.project)
    
    try:
        project_store = ProjectStore(project_path)
        ctx['project_store'] = project_store
    except Exception as e:
        formatter.format_error(f"Failed to load project from {project_path}: {e}")
        sys.exit(1)
        
    try:
        audit_db_path = os.path.join(project_path, AUDIT_DB_FILENAME)
        if not os.path.exists(audit_db_path):
            audit_db_path = os.path.join(project_path, "databases", AUDIT_DB_FILENAME)
            
        if os.path.exists(audit_db_path):
            audit_db = AuditDatabase(audit_db_path)
            audit_db.connect()
            ctx['audit_db'] = audit_db
    except Exception as e:
        # Audit DB is optional for non-audit commands
        pass
        
    # Dispatch to handler
    if hasattr(args, 'func'):
        args.func(args, ctx, formatter)
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()