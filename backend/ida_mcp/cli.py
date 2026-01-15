import sys
from . import export_cmd
from . import server_cmd

def main():
    if len(sys.argv) < 2:
        print("Usage: ida-mcp <command> [args]")
        print("Commands:")
        print("  export  - Export IDA database")
        print("  serve   - Start MCP server")
        sys.exit(1)

    command = sys.argv[1]
    
    # Check if user is asking for help on the main command
    if command in ("-h", "--help"):
        print("Usage: ida-mcp <command> [args]")
        print("Commands:")
        print("  export  - Export IDA database")
        print("  serve   - Start MCP server")
        sys.exit(0)

    # Remove command from argv so sub-scripts don't see it
    # We keep sys.argv[0] as the program name
    del sys.argv[1]

    if command == "export":
        export_cmd.main()
    elif command == "serve":
        server_cmd.main()
    else:
        print(f"Unknown command: {command}")
        print("Available commands: export, serve")
        sys.exit(1)

if __name__ == "__main__":
    main()
