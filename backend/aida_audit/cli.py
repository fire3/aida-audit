import sys
import argparse
from . import export_cmd
from . import server_cmd
from . import query_cmd


def main():
    if len(sys.argv) < 2:
        print("AIDA-AUDIT - Binary Analysis Export & MCP Server")
        print()
        print("Usage: aida-audit <command> [options]")
        print()
        print("Commands:")
        print("  export  Export binary analysis results to SQLite database")
        print("          (auto-initializes workspace with MCP configs)")
        print("  serve   Start the MCP server with web UI")
        print("  query   Query binary analysis and audit data from CLI")
        print()
        print("For more information, run: aida-audit <command> -h")
        sys.exit(1)

    command = sys.argv[1]

    if command in ("-h", "--help"):
        print("AIDA-AUDIT - Binary Analysis Export & MCP Server")
        print()
        print("Usage: aida-audit <command> [options]")
        print()
        print("Commands:")
        print("  export  Export binary analysis results to SQLite database")
        print("          (auto-initializes workspace with MCP configs)")
        print("  serve   Start the MCP server with web UI")
        print("  query   Query binary analysis and audit data from CLI")
        print()
        print("For more information, run: aida-audit <command> -h")
        sys.exit(0)

    del sys.argv[1]

    if command == "export":
        export_cmd.main()
    elif command == "serve":
        server_cmd.main()
    elif command == "query":
        query_cmd.main()
    else:
        print(f"error: unknown command '{command}'")
        print("Run 'aida-audit' for usage information.")
        sys.exit(1)


if __name__ == "__main__":
    main()