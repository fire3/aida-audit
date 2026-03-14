import sys
import argparse
from . import export_cmd
from . import server_cmd


def main():
    if len(sys.argv) < 2:
        print("Usage: aida-cli <command> [options]")
        print()
        print("Commands:")
        print("  export  Export binary analysis results to SQLite database")
        print("  serve   Start the MCP server with web UI")
        print()
        print("Run 'aida-cli <command> -h' for more information on a command.")
        sys.exit(1)

    command = sys.argv[1]

    if command in ("-h", "--help"):
        print("Usage: aida-cli <command> [options]")
        print()
        print("Commands:")
        print("  export  Export binary analysis results to SQLite database")
        print("  serve   Start the MCP server with web UI")
        print()
        print("Run 'aida-cli <command> -h' for more information on a command.")
        sys.exit(0)

    del sys.argv[1]

    if command == "export":
        export_cmd.main()
    elif command == "serve":
        server_cmd.main()
    else:
        print(f"error: unknown command '{command}'")
        print("Run 'aida-cli' for usage information.")
        sys.exit(1)


if __name__ == "__main__":
    main()