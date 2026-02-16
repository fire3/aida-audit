import sys
import argparse
from . import export_cmd
from . import server_cmd
from . import scan_cmd
from . import config_cmd
from . import workspace_cmd

def _print_main_help():
    print("Usage: aida_cli <command> [args]")
    print("Commands:")
    print("  export  - Export MCP database")
    print("  serve   - Start MCP server")
    print("  workspace - Initialize a local workspace")
    print("  config  - Interactive LLM configuration")
    print("  scan    - Run IDA Microcode taint scan")

def main():
    if len(sys.argv) < 2:
        _print_main_help()
        sys.exit(1)

    command = sys.argv[1]
    
    # Check if user is asking for help on the main command
    if command in ("-h", "--help"):
        _print_main_help()
        sys.exit(0)

    # Remove command from argv so sub-scripts don't see it
    # We keep sys.argv[0] as the program name
    del sys.argv[1]

    if command == "export":
        export_cmd.main()
    elif command == "serve":
        server_cmd.main()
    elif command == "config":
        config_cmd.main()
    elif command == "install":
        print("Error: 'install' command is deprecated. Use 'workspace' instead.")
        sys.exit(1)
    elif command == "workspace":
        workspace_cmd.main()
    elif command == "scan":
        scan_cmd.main()
    else:
        print(f"Unknown command: {command}")
        print("Available commands: export, serve, config, workspace, scan")
        sys.exit(1)

if __name__ == "__main__":
    main()
