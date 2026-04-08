import json
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax

class OutputFormatter:
    def __init__(self, format_type="text"):
        self.format_type = format_type
        self.console = Console()

    def format_output(self, data, entity_type="result", list_view=False):
        if self.format_type == "json":
            print(json.dumps({"success": True, "data": data}, indent=2))
        elif self.format_type == "markdown":
            self._format_markdown(data, entity_type, list_view)
        else:
            self._format_text(data, entity_type, list_view)

    def format_error(self, error_msg):
        if self.format_type == "json":
            print(json.dumps({"success": False, "error": error_msg}, indent=2))
        elif self.format_type == "markdown":
            print(f"**Error:** {error_msg}")
        else:
            self.console.print(f"[bold red]Error:[/bold red] {error_msg}")

    def _format_text(self, data, entity_type, list_view):
        if not data:
            self.console.print(f"[yellow]No {entity_type} found.[/yellow]")
            return

        if list_view:
            if not isinstance(data, list):
                data = [data]
            
            if not data:
                self.console.print(f"[yellow]No {entity_type} found.[/yellow]")
                return
            
            table = Table(title=f"{entity_type.capitalize()} List")
            keys = list(data[0].keys())
            for key in keys:
                table.add_column(key.capitalize())
                
            for item in data:
                row = [str(item.get(k, "")) for k in keys]
                table.add_row(*row)
            self.console.print(table)
        else:
            # Detail view
            table = Table(title=f"{entity_type.capitalize()} Details", show_header=True)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="magenta")
            
            # Separate complex fields like pseudocode or calls
            complex_fields = {}
            for k, v in data.items():
                if k in ("pseudocode", "callees", "callers") or isinstance(v, (list, dict)):
                    complex_fields[k] = v
                else:
                    table.add_row(k.capitalize(), str(v))
            
            self.console.print(table)
            
            # Print complex fields
            if "pseudocode" in complex_fields and complex_fields["pseudocode"]:
                self.console.print("\n[bold cyan][Pseudocode][/bold cyan]")
                syntax = Syntax(complex_fields["pseudocode"], "c", theme="monokai", line_numbers=True)
                self.console.print(syntax)
                
            if "callers" in complex_fields and complex_fields["callers"]:
                self.console.print("\n[bold cyan][Callers][/bold cyan]")
                for c in complex_fields["callers"]:
                    self.console.print(f"- {c}")
                    
            if "callees" in complex_fields and complex_fields["callees"]:
                self.console.print("\n[bold cyan][Callees][/bold cyan]")
                for c in complex_fields["callees"]:
                    self.console.print(f"- {c}")

    def _format_markdown(self, data, entity_type, list_view):
        if not data:
            print(f"No {entity_type} found.")
            return
            
        print(f"### {entity_type.capitalize()} Information\n")
        
        if list_view:
            if not isinstance(data, list):
                data = [data]
            
            if not data:
                print(f"No {entity_type} found.")
                return
                
            keys = list(data[0].keys())
            header = "| " + " | ".join([k.capitalize() for k in keys]) + " |"
            separator = "| " + " | ".join(["---"] * len(keys)) + " |"
            
            print(header)
            print(separator)
            
            for item in data:
                row = "| " + " | ".join([str(item.get(k, "")).replace("|", "\\|").replace("\n", " ") for k in keys]) + " |"
                print(row)
        else:
            print("| Property | Value |")
            print("| --- | --- |")
            
            complex_fields = {}
            for k, v in data.items():
                if k in ("pseudocode", "callees", "callers") or isinstance(v, (list, dict)):
                    complex_fields[k] = v
                else:
                    print(f"| {k.capitalize()} | {str(v).replace('|', '\\|').replace(chr(10), ' ')} |")
            
            if "pseudocode" in complex_fields and complex_fields["pseudocode"]:
                print("\n#### Pseudocode")
                print("```c")
                print(complex_fields["pseudocode"])
                print("```")
                
            if "callers" in complex_fields and complex_fields["callers"]:
                print("\n#### Callers")
                for c in complex_fields["callers"]:
                    print(f"* {c}")
                    
            if "callees" in complex_fields and complex_fields["callees"]:
                print("\n#### Callees")
                for c in complex_fields["callees"]:
                    print(f"* {c}")
