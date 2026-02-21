import json
import re
import inspect
import traceback
import os
import io
import logging
from typing import Any, Dict, List, Optional, Union, get_type_hints
from .project_store import ProjectStore
from . import audit_mcp_tools

def mcp_tool(name=None):
    """Decorator to mark a method as an MCP tool."""
    def decorator(func):
        func._mcp_tool_config = {
            "name": name or func.__name__,
        }
        return func
    return decorator

class McpError(Exception):
    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

class McpService:
    def __init__(self, project_store: ProjectStore):
        self.project_store = project_store

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get the list of registered tools with generated schemas."""
        tools = []
        for attr_name in dir(self):
            method = getattr(self, attr_name)
            if hasattr(method, "_mcp_tool_config"):
                cfg = method._mcp_tool_config
                
                # Generate schema and handler
                schema = self._generate_schema(method)
                handler = self._create_handler(method)
                
                description = inspect.cleandoc(method.__doc__) if method.__doc__ else ""
                
                tools.append({
                    "name": cfg["name"],
                    "description": description,
                    "inputSchema": schema,
                    "handler": handler
                })
        return tools

    def get_tools_metadata(self) -> List[Dict[str, Any]]:
        """Get metadata of registered tools (without handlers) for API display."""
        tools = self.get_tools()
        # Remove handler from each tool for JSON serialization
        return [{k: v for k, v in t.items() if k != "handler"} for t in tools]

    def _generate_schema(self, method) -> Dict[str, Any]:
        """Generate JSON schema from method signature."""
        sig = inspect.signature(method)
        type_hints = get_type_hints(method)
        
        properties = {}
        required = []
        
        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue
                
            param_type = type_hints.get(param_name, Any)
            json_type = self._python_type_to_json_type(param_type)
            
            properties[param_name] = json_type
            
            if param.default == inspect.Parameter.empty:
                required.append(param_name)
                
        return {
            "type": "object",
            "properties": properties,
            "required": required
        }

    def _python_type_to_json_type(self, py_type) -> Dict[str, Any]:
        """Convert Python type to JSON schema type."""
        if py_type == str:
            return {"type": "string"}
        elif py_type == int:
            return {"type": "integer"}
        elif py_type == bool:
            return {"type": "boolean"}
        elif py_type == float:
            return {"type": "number"}
        elif py_type == list or getattr(py_type, "__origin__", None) == list:
            return {"type": "array"}
        elif py_type == dict or getattr(py_type, "__origin__", None) == dict:
            return {"type": "object"}
        elif getattr(py_type, "__origin__", None) == Union:
            # Handle Optional (Union[T, None]) or Union[A, B]
            args = py_type.__args__
            # Simple case: Optional[T] -> T's type
            non_none = [a for a in args if a is not type(None)]
            if len(non_none) == 1:
                return self._python_type_to_json_type(non_none[0])
            # Complex Union: treat as any/string for now or multi-type
            return {} 
        else:
            return {} # Any or unknown

    def _create_handler(self, method):
        """Create a wrapper handler that binds arguments."""
        def handler(args: Dict[str, Any]):
            # Bind arguments to method signature
            sig = inspect.signature(method)
            try:
                bound_args = sig.bind(**args)
                bound_args.apply_defaults()
            except TypeError as e:
                 raise McpError("INVALID_ARGUMENT", str(e))
            return method(*bound_args.args, **bound_args.kwargs)
        return handler

    def _get_binary(self, binary_name: str):
        if not binary_name:
            raise KeyError("binary_name_required")
        b = self.project_store.get_binary(binary_name)
        if not b:
            raise LookupError(f"binary_not_found: {binary_name}")
        return b

    # --- Tool Definitions ---

    #@mcp_tool(name="get_flare_emu_dsl_guide")
    def get_flare_emu_dsl_guide(self) -> str:
        """Retrieve the official guide for writing Flare-Emu Text DSL scripts.

        Use this tool to learn the syntax and features of the Flare-Emu DSL, which is used for dynamic emulation tasks.
        The guide includes examples of memory allocation, function calls, hooking, and assertions.

        Returns:
            str: The full markdown content of the DSL guide.
        """
        from .flare_emu_mcp_tools import get_flare_emu_dsl_guide_impl
        return get_flare_emu_dsl_guide_impl()

    #@mcp_tool(name="run_flare_emu_dsl")
    def run_flare_emu_dsl(self, binary_name: str, script: str) -> Dict[str, Any]:
        """Execute a Flare-Emu Text DSL script on a specific binary.

        Use this tool to perform dynamic analysis tasks such as emulating functions, fuzzing inputs, or verifying behavior.
        The script should follow the syntax defined in the DSL guide.

        Args:
            binary_name: The unique name of the binary to analyze.
            script: The DSL script content to execute.

        Returns:
            dict: A dictionary containing the execution results:
                - 'success' (bool): Whether the execution completed without unhandled exceptions.
                - 'logs' (list): Captured log messages from the emulation session.
                - 'variables' (dict): Final state of DSL variables.
                - 'coverage_count' (int): Number of unique instructions executed.
                - 'trace' (list): Execution trace (if enabled in script).
                - 'error' (str): Error message if execution failed.
                - 'crash_context' (dict): Register/stack state if a crash occurred.
        """
        try:
            from .flare_emu_mcp_tools import run_flare_emu_dsl_impl
            return run_flare_emu_dsl_impl(self.project_store, binary_name, script)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except Exception as e:
            raise McpError("INTERNAL_ERROR", f"Emulation failed: {str(e)}\n{traceback.format_exc()}")

    @mcp_tool(name="get_project_overview")
    def get_project_overview(self) -> Dict[str, Any]:
        """Retrieve a high-level overview of the current analysis project.

        Use this tool to understand the scope of the project, including the number of binaries analyzed and the available analysis capabilities.
        This is typically the first step to verify project status before diving into specific binaries.

        Returns:
            dict: A dictionary containing project statistics:
                - 'binaries_count' (int): Total number of binaries in the project.
                - 'capabilities' (dict): Supported analysis features (e.g., disassembly, decompilation).
        """
        return self.project_store.get_overview()

    @mcp_tool(name="get_project_binaries")
    def get_project_binaries(self, offset: int = 0, limit: int = 50, filters: dict = None, detail: bool = False) -> List[Dict[str, Any]]:
        """List all binaries available in the current project with pagination support.

        Use this tool to discover available binaries for analysis. It returns basic metadata for each binary, allowing you to select specific targets for deeper inspection.

        Args:
            offset: The starting index for pagination. Use 0 for the first page.
            limit: The maximum number of binaries to return (max 50). Use a lower value for quick checks.
            filters: A dictionary of key-value pairs to filter the results (e.g., {'arch': 'x86'}).
            detail: If True, returns extended metadata for each binary (slower). Default is False.

        Returns:
            list: A list of binary metadata objects, each containing 'name', 'size', 'arch', etc.
        """
        return self.project_store.get_project_binaries(offset, limit, filters, detail)

    @mcp_tool(name="get_binary_metadata")
    def get_binary_metadata(self, binary_name: str) -> Dict[str, Any]:
        """Retrieve detailed metadata for a specific binary file.

        Use this tool to get technical details about a binary, such as its architecture (x86/ARM), file format (PE/ELF), entry point, and other properties.
        This helps in understanding the target environment before analyzing code.

        Args:
            binary_name: The unique name of the binary to inspect (e.g., 'ntoskrnl.exe').

        Returns:
            dict: A dictionary containing detailed binary properties: architecture, endianness, entry_point, file_format, etc.
        """
        return self._get_binary(binary_name).get_extended_metadata()

    #@mcp_tool(name="list_binary_sections")
    def list_binary_sections(self, binary_name: str) -> List[Dict[str, Any]]:
        """Retrieve the list of sections (e.g., .text, .data) in the specified binary.

        Use this tool to map out the binary's memory layout. It helps identify code regions (executable) versus data regions (readable/writable).

        Args:
            binary_name: The unique name of the binary to analyze.

        Returns:
            list: A list of section objects, each containing:
                - 'name': Section name.
                - 'start_address': Start address in memory (hex string).
                - 'size': Size in bytes.
        """
        return self._get_binary(binary_name).list_sections()

    #@mcp_tool(name="list_binary_segments")
    def list_binary_segments(self, binary_name: str) -> List[Dict[str, Any]]:
        """Retrieve the list of segments in the specified binary.

        Use this tool to understand the memory segmentation of the binary, including permissions (read, write, execute) for each segment.

        Args:
            binary_name: The unique name of the binary to analyze.

        Returns:
            list: A list of segment objects, each containing:
                - 'name': Segment name.
                - 'start_address': Start address (hex string).
                - 'size': Size in bytes.
                - 'permissions': Permission flags (e.g., 'R-X').
        """
        return self._get_binary(binary_name).list_segments()


    @mcp_tool(name="list_binary_symbols")
    def list_binary_symbols(self, binary_name: str, query: str = None, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Search and list symbols (functions, variables, labels) in the binary.

        Use this tool to find specific symbols by name or to browse available symbols. This is useful for locating known functions or global variables.

        Args:
            binary_name: The unique name of the binary to search.
            query: A partial name or keyword to filter symbols (case-insensitive). Optional.
            offset: The starting index for pagination (default: 0).
            limit: The maximum number of symbols to return (max 50).

        Returns:
            list: A list of symbol objects, each containing 'name', 'address', and 'type'.
        """
        return self._get_binary(binary_name).list_symbols(query, offset, limit)

    @mcp_tool(name="resolve_address")
    def resolve_address(self, binary_name: str, address: Union[str, int]) -> Dict[str, Any]:
        """Resolve the context of a specific memory address.

        Use this tool to determine what resides at a given address: which function it belongs to, which section it falls into, and what symbol (if any) is associated with it.

        Args:
            binary_name: The unique name of the binary.
            address: The memory address to resolve. MUST be a string if using hex (e.g., "0x401000").

        Returns:
            dict: Contextual information including:
                - 'function': The containing function (if any).
                - 'segment': The containing segment.
                - 'symbol': The nearest symbol.
        """
        try:
            return self._get_binary(binary_name).resolve_address(address)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))
        except Exception as e:
            raise McpError("INTERNAL_ERROR", str(e))

    @mcp_tool(name="resolve_symbol")
    def resolve_symbol(self, binary_name: str, symbol_name: str) -> List[Dict[str, Any]]:
        """Resolve a symbol name to its address and details (function or global variable).
        
        Use this tool to get information about a symbol, such as a function or global variable.
        For global variables, it returns the definition, size, and value representation if available.
        For functions, it returns the address and size.
        
        Args:
            binary_name: The unique name of the binary.
            symbol_name: The name of the symbol to resolve.
            
        Returns:
            list: A list of matching symbols with their details.
        """
        try:
            return self._get_binary(binary_name).resolve_symbol(symbol_name)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except Exception as e:
            raise McpError("INTERNAL_ERROR", str(e))

    #@mcp_tool(name="get_binary_bytes")
    def get_binary_bytes(self, binary_name: str, address: Union[str, int], length: int, format_type: str = None) -> str:
        """Read raw bytes from a specific memory address in the binary.

        Use this tool to inspect raw data, such as headers, strings, or unknown data structures.
        Do not use this for code analysis; use disassembly tools instead.

        Args:
            binary_name: The unique name of the binary.
            address: The starting memory address. MUST be a string if using hex (e.g., "0x401000").
            length: The number of bytes to read (must be positive).
            format_type: The output format. Options: 'hex' (default) or 'base64'.

        Returns:
            str: The read bytes formatted as a hex string (e.g., '4d5a90...') or base64 string.
        """
        try:
            return self._get_binary(binary_name).get_bytes(address, length, format_type)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except RuntimeError as e:
            raise McpError("UNSUPPORTED", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))

    @mcp_tool(name="get_binary_decoded_data")
    def get_binary_decoded_data(self, binary_name: str, address: Union[str, int], length: int) -> Dict[str, Any]:
        """Decode raw bytes at an address into a structured format (if possible).

        Use this tool when you suspect an address contains a specific data type (string, pointer, etc.) and want the tool to attempt automatic decoding.

        Args:
            binary_name: The unique name of the binary.
            address: The starting memory address. MUST be a string if using hex (e.g., "0x401000").
            length: The number of bytes to analyze.

        Returns:
            dict: A dictionary containing the 'decoded_value' (if successful) and the 'type' (e.g., 'string', 'pointer').
        """
        try:
            return self._get_binary(binary_name).get_decoded_data(address, length)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))
        except Exception as e:
            raise McpError("INTERNAL_ERROR", str(e))

    @mcp_tool(name="get_binary_disassembly_text")
    def get_binary_disassembly_text(self, binary_name: str, start_address: Union[str, int], end_address: Union[str, int]) -> str:
        """Retrieve assembly instructions for a specific memory range.

        Use this tool to analyze a custom block of code that might not correspond to a single function.
        This provides the raw assembly instructions (mnemonics and operands).

        Args:
            binary_name: The unique name of the binary.
            start_address: The starting memory address. MUST be a string if using hex (e.g., "0x401000").
            end_address: The ending memory address. MUST be a string if using hex (e.g., "0x401050").

        Returns:
            str: A text block containing the assembly instructions, one per line.
        """
        try:
            return self._get_binary(binary_name).get_disassembly_text(start_address, end_address)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))
        except Exception as e:
            raise McpError("INTERNAL_ERROR", str(e))

    @mcp_tool(name="get_binary_function_disassembly_text")
    def get_binary_function_disassembly_text(self, binary_name: str, function_address: Union[str, int]) -> str:
        """Retrieve the complete assembly code for a specific function.

        Use this tool to study the implementation details of a function at the assembly level.
        It returns the instructions for the entire function body.

        Args:
            binary_name: The unique name of the binary.
            function_address: The entry address of the function. MUST be a string if using hex (e.g., "0x401000").

        Returns:
            str: A text block containing the function's assembly code.
        """
        try:
            return self._get_binary(binary_name).get_function_disassembly_text(function_address)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))
        except Exception as e:
            raise McpError("INTERNAL_ERROR", str(e))

    @mcp_tool(name="get_binary_disassembly_context")
    def get_binary_disassembly_context(self, binary_name: str, address: Union[str, int], context_lines: int = 10) -> str:
        """Retrieve assembly instructions surrounding a specific address.

        Use this tool to see the context of an instruction (lines before and after) without fetching the entire function.
        Useful for quick checks or understanding the immediate neighborhood of an address.

        Args:
            binary_name: The unique name of the binary.
            address: The central memory address. MUST be a string if using hex (e.g., "0x401000").
            context_lines: The number of instructions to show before and after the target address (default: 10).

        Returns:
            str: A text block showing the assembly instructions with the target address in the middle.
        """
        try:
            return self._get_binary(binary_name).get_disassembly_context(address, context_lines)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))
        except Exception as e:
            raise McpError("INTERNAL_ERROR", str(e))

    @mcp_tool(name="list_binary_functions")
    def list_binary_functions(self, binary_name: str, query: str = None, offset: int = 0, limit: int = 50, filters: dict = None) -> List[Dict[str, Any]]:
        """List functions available in the binary.

        Use this tool to explore the functions defined in the binary. You can search by name or list them sequentially.
        This is essential for identifying interesting code regions to analyze.

        Args:
            binary_name: The unique name of the binary.
            query: A partial string to filter function names (e.g., 'main', 'ssl'). Optional.
            offset: The starting index for pagination (default: 0).
            limit: The maximum number of functions to return (max 50).
            filters: Additional criteria to filter functions (e.g., size range). Optional.

        Returns:
            list: A list of function objects, each containing 'name', 'address', and 'size'.
        """
        return self._get_binary(binary_name).list_functions(query, offset, limit, filters)

    @mcp_tool(name="get_binary_function_by_name")
    def get_binary_function_by_name(self, binary_name: str, names: Union[str, List[str]], match: str = None) -> List[Dict[str, Any]]:
        """Find functions by their name(s).

        Use this tool when you have a specific function name or pattern in mind and want to find its address and details.
        Supports exact matching, substring matching, and regular expressions.

        Args:
            binary_name: The unique name of the binary.
            names: The function name(s) to search for. Can be a single string or a list of strings.
            match: The matching strategy. Options: 'exact' (default), 'contains', or 'regex'.

        Returns:
            list: A list of matching function objects with their metadata.
        """
        if isinstance(names, str):
            # Try parsing as JSON if it looks like one, or wrap in list
            names = self._coerce_json_list(names)
        if not isinstance(names, list):
            names = [names]
        return self._get_binary(binary_name).get_functions_by_name(names, match)

    @mcp_tool(name="get_binary_function_by_address")
    def get_binary_function_by_address(self, binary_name: str, addresses: Union[str, int, List[Union[str, int]]]) -> List[Dict[str, Any]]:
        """Retrieve function details for specific address(es).

        Use this tool to get metadata (name, size, start/end) for a function given its entry address.
        This is useful when you have an address (e.g., from a cross-reference) and need to know which function it corresponds to.

        Args:
            binary_name: The unique name of the binary.
            addresses: The function address(es) to query. MUST be a string if using hex (e.g., "0x401000"). Can be a single value or a list.

        Returns:
            list: A list of function metadata objects corresponding to the requested addresses.
        """
        try:
            if isinstance(addresses, (str, int)):
                 addresses = self._coerce_json_list(addresses)
            if not isinstance(addresses, list):
                addresses = [addresses]
            return self._get_binary(binary_name).get_functions_by_address(addresses)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))
        except Exception as e:
            raise McpError("INTERNAL_ERROR", str(e))

    @mcp_tool(name="get_binary_function_pseudocode_by_address")
    def get_binary_function_pseudocode_by_address(self, binary_name: str, addresses: Union[str, int, List[Union[str, int]]], options: dict = None) -> List[Dict[str, Any]]:
        """Decompile a function into C-style pseudocode.

        Use this tool to get a high-level C-like representation of the assembly code.
        This is the primary tool for understanding complex logic, as it abstracts away registers and stack management.

        Args:
            binary_name: The unique name of the binary.
            addresses: The entry address(es) of the function(s) to decompile. MUST be a string if using hex (e.g., "0x401000"). Can be a single value or a list.
            options: Decompilation settings (optional).

        Returns:
            list: A list of results, each containing the 'pseudocode' string for the requested function.
        """
        try:
            if isinstance(addresses, (str, int)):
                 addresses = self._coerce_json_list(addresses)
            if not isinstance(addresses, list):
                addresses = [addresses]
            return self._get_binary(binary_name).get_pseudocode_by_address(addresses, options)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))
        except Exception as e:
            raise McpError("INTERNAL_ERROR", str(e))

    @mcp_tool(name="get_binary_function_callees")
    def get_binary_function_callees(self, binary_name: str, function_address: Union[str, int], depth: int = None, limit: int = None) -> List[Dict[str, Any]]:
        """Identify which functions are called by a specific function (outbound calls).

        Use this tool to understand the dependencies of a function: what other subroutines does it invoke?
        This helps in tracing the control flow downwards.

        Args:
            binary_name: The unique name of the binary.
            function_address: The entry address of the caller function. MUST be a string if using hex (e.g., "0x401000").
            depth: The depth of the call graph to traverse (default: 1, immediate callees).
            limit: The maximum number of callees to return.

        Returns:
            list: A list of called functions, including their addresses and names.
        """
        try:
            return self._get_binary(binary_name).get_callees(function_address, depth, limit)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))
        except Exception as e:
            raise McpError("INTERNAL_ERROR", str(e))

    @mcp_tool(name="get_binary_function_callers")
    def get_binary_function_callers(self, binary_name: str, function_address: Union[str, int], depth: int = None, limit: int = None) -> List[Dict[str, Any]]:
        """Identify which functions call a specific function (inbound calls).

        Use this tool to find usage examples (X-refs) of a function.
        This is crucial for understanding how a function is used throughout the program and tracing execution paths upwards.

        Args:
            binary_name: The unique name of the binary.
            function_address: The entry address of the target function. MUST be a string if using hex (e.g., "0x401000").
            depth: The depth of the call graph to traverse (default: 1, immediate callers).
            limit: The maximum number of callers to return.

        Returns:
            list: A list of calling functions (call sites), including their addresses and names.
        """
        try:
            return self._get_binary(binary_name).get_callers(function_address, depth, limit)
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))
        except Exception as e:
            raise McpError("INTERNAL_ERROR", str(e))

    def get_binary_cross_references_to_address(self, binary_name: str, address: Union[str, int], offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Get cross references to an address.

        Args:
            binary_name: Binary name (string).
            address: Target address (hex string or integer).
            offset: Start index for pagination (default: 0).
            limit: Maximum number of xrefs to return (default: 50).
        Returns:
            list: List of dictionaries, each representing a cross reference.
        """
        return self._get_binary(binary_name).get_xrefs_to_address(address, offset, limit, None)

    def get_binary_cross_references_from_address(self, binary_name: str, address: Union[str, int], offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Get cross references from an address.

        Args:
            binary_name: Binary name (string).
            address: Source address (hex string or integer).
            offset: Start index for pagination (default: 0).
            limit: Maximum number of xrefs to return (default: 50).
        Returns:
            list: List of dictionaries, each representing a cross reference.
        """
        return self._get_binary(binary_name).get_xrefs_from_address(address, offset, limit)

    @mcp_tool(name="get_binary_cross_references")
    def get_binary_cross_references(self, binary_name: str, address: Union[str, int], offset: int = 0, limit: int = 50) -> Dict[str, List[Dict[str, Any]]]:
        """Retrieve cross-references (xrefs) to and from a specific address.

        Use this tool to find:
        1. Who refers to this address (Code X-refs or Data X-refs).
        2. What this address refers to (e.g., calls, string usage).
        This is a comprehensive tool for analyzing relationships between code and data.

        Args:
            binary_name: The unique name of the binary.
            address: The memory address to analyze. MUST be a string if using hex (e.g., "0x401000").
            offset: Pagination offset for the results list (default: 0).
            limit: Max number of xrefs to return per direction (max 50).

        Returns:
            dict: An object with 'to' (incoming references) and 'from' (outgoing references) lists.
        """
        try:
            return {
                "to": self.get_binary_cross_references_to_address(binary_name, address, offset, limit),
                "from": self.get_binary_cross_references_from_address(binary_name, address, offset, limit)
            }
        except LookupError as e:
            raise McpError("NOT_FOUND", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))
        except Exception as e:
            raise McpError("INTERNAL_ERROR", str(e))


    @mcp_tool(name="list_binary_strings")
    def list_binary_strings(self, binary_name: str, query: str = None, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for strings found within the binary.

        Use this tool to find text data (ASCII, Unicode, etc.).
        Searching for specific strings (e.g., "error", "password") is a common starting point for finding relevant code logic.

        Args:
            binary_name: The unique name of the binary.
            query: A specific string or substring to search for (case-insensitive). Optional.
            offset: The starting index for pagination.
            limit: The maximum number of strings to return (max 50).

        Returns:
            list: A list of string objects, including 'value', 'address', and 'encoding'.
        """
        return self._get_binary(binary_name).list_strings(query, None, None, offset, limit)

    @mcp_tool(name="list_binary_imports")
    def list_binary_imports(self, binary_name: str, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """List external functions imported by the binary (Imports).

        Use this tool to see what external libraries and APIs the binary relies on (e.g., 'kernel32.dll', 'CreateFile').
        This gives strong clues about the binary's behavior (file I/O, network, GUI, etc.).

        Args:
            binary_name: The unique name of the binary.
            offset: The starting index for pagination.
            limit: The maximum number of imports to return (max 50).

        Returns:
            list: A list of import objects, each containing 'name', 'library', and 'address'.
        """
        return self._get_binary(binary_name).list_imports(offset, limit)

    @mcp_tool(name="list_binary_exports")
    def list_binary_exports(self, binary_name: str, query: str = None, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """List functions exported by the binary (Exports).

        Use this tool to identify the public API of a DLL or shared library.
        These are the entry points intended for external use.

        Args:
            binary_name: The unique name of the binary.
            query: A partial name to filter exports. Optional.
            offset: The starting index for pagination.
            limit: The maximum number of exports to return (max 50).

        Returns:
            list: A list of export objects, each containing 'name', 'ordinal', and 'address'.
        """
        return self._get_binary(binary_name).list_exports(query, offset, limit)

    @mcp_tool(name="search_string_symbol_in_binary")
    def search_string_in_binary(self, binary_name: str, search_string: str, match: str = "contains") -> List[Dict[str, Any]]:
        """Search for a string within a specific binary.

        Use this tool to find a specific text string within one binary.
        This is similar to `search_strings` but scoped to a single binary.

        Args:
            binary_name: The unique name of the binary.
            search_string: The text or symbol name to search for.
            match: The matching strategy. Options: 'contains' (default), 'exact', 'regex'.

        Returns:
            list: A list of matches found in the binary.
        """
        b = self._get_binary(binary_name)
        match = (match or "contains").lower()
        if match == "exact":
            hits = b.list_strings(query=search_string, offset=0, limit=500)
            hits = [h for h in hits if h.get("string") == search_string]
            return hits
        if match == "regex":
            try:
                rx = re.compile(search_string)
            except Exception as e:
                raise McpError("INVALID_ARGUMENT", "regex_invalid", {"error": str(e)})
            hits = b.list_strings(query=None, offset=0, limit=500)
            hits = [h for h in hits if isinstance(h.get("string"), str) and rx.search(h["string"])]
            return hits
        return b.list_strings(query=search_string, offset=0, limit=500)

    @mcp_tool(name="search_immediates_in_binary")
    def search_immediates_in_binary(self, binary_name: str, value: Any, width: int = None, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for constant values (immediates) in the code.

        Use this tool to find where specific constants (e.g., magic numbers, error codes like 0x80040154) are used.
        This is very effective for locating code handling specific error conditions or cryptographic constants.

        Args:
            binary_name: The unique name of the binary.
            value: The constant value to search for (integer or hex string).
            width: The size of the value in bytes (optional).
            offset: The starting index for pagination.
            limit: The maximum number of matches to return (max 50).

        Returns:
            list: A list of instructions or data locations using the value.
        """
        return self._get_binary(binary_name).search_immediates(value, width, offset, limit)

    @mcp_tool(name="search_bytes_pattern_in_binary")
    def search_bytes_pattern_in_binary(self, binary_name: str, pattern: str, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for a sequence of bytes (binary signature).

        Use this tool to find code or data matching a specific byte signature.
        Supports wildcards (??) for matching variable bytes.
        Example pattern: "55 8B EC" (standard function prologue).

        Args:
            binary_name: The unique name of the binary.
            pattern: The byte sequence to search for (hex string with spaces, e.g., "E8 ?? ?? ?? ??").
            offset: The starting index for pagination.
            limit: The maximum number of matches to return (max 50).

        Returns:
            list: A list of addresses where the pattern matches.
        """
        b = self._get_binary(binary_name)
        try:
            return b.search_bytes_pattern(pattern, offset, limit)
        except RuntimeError as e:
            raise McpError("UNSUPPORTED", str(e))
        except ValueError as e:
            raise McpError("INVALID_ARGUMENT", str(e))

    @mcp_tool(name="search_strings_in_project")
    def search_strings_in_project(self, search_string: str, match: str = "contains", offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for strings across ALL binaries in the project.

        Use this tool when you don't know which binary contains a specific string.
        It aggregates results from all loaded binaries.

        Args:
            search_string: The text content to search for.
            match: The matching strategy. Options: 'contains' (default), 'exact', 'regex'.
            offset: The starting index for pagination.
            limit: The maximum number of matches to return (max 50).

        Returns:
            list: A list of matches, each containing 'binary', 'string', and 'address'.
        """
        match = (match or "contains").lower()
        offset = max(0, offset)
        limit = min(500, max(1, limit))
        
        all_hits = []
        for b in self.project_store.list_binaries():
            hits = []
            if match == "exact":
                hits = b.list_strings(query=search_string, offset=0, limit=500)
                hits = [h for h in hits if h.get("string") == search_string]
            elif match == "regex":
                try:
                    rx = re.compile(search_string)
                except Exception as e:
                    raise McpError("INVALID_ARGUMENT", "regex_invalid", {"error": str(e)})
                cand = b.list_strings(query=None, offset=0, limit=500)
                hits = [h for h in cand if isinstance(h.get("string"), str) and rx.search(h["string"])]
            else:
                hits = b.list_strings(query=search_string, offset=0, limit=500)
            
            for h in hits:
                all_hits.append({"binary": b.display_name, **h})
        return all_hits[offset : offset + limit]

    @mcp_tool(name="search_functions_in_project")
    def search_functions_in_project(self, function_name: str, match: str = "contains", offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for exported functions across ALL binaries in the project.

        Use this tool to find where a specific API is exported within the entire project scope.
        Useful for finding specific library functions in a multi-binary analysis.

        Args:
            function_name: The name of the function to search for.
            match: The matching strategy. Options: 'contains' (default), 'exact', 'regex'.
            offset: The starting index for pagination.
            limit: The maximum number of matches to return (max 50).

        Returns:
            list: A list of matches, each containing 'binary', 'function_name', and 'address'.
        """
        match = (match or "contains").lower()
        offset = max(0, offset)
        limit = min(500, max(1, limit))
        
        hits = []
        for b in self.project_store.list_binaries():
            found_funcs = []
            if match == "exact":
                # list_functions query is typically "contains", so we might need to filter manually if list_functions doesn't support exact
                # But list_functions usually does "contains".
                # Let's fetch with query and filter.
                funcs = b.list_functions(query=function_name, limit=500)
                found_funcs = [f for f in funcs if f.get("name") == function_name]
            elif match == "contains":
                found_funcs = b.list_functions(query=function_name, limit=500)
            else:
                # Regex
                try:
                    rx = re.compile(function_name)
                except Exception as e:
                    raise McpError("INVALID_ARGUMENT", "regex_invalid", {"error": str(e)})
                funcs = b.list_functions(query=None, limit=5000) # Fetch more for regex
                found_funcs = [f for f in funcs if f.get("name") and rx.search(f["name"])]
            
            for f in found_funcs:
                hits.append({"binary": b.display_name, "function": f})
                
        return hits[offset : offset + limit]

    @mcp_tool(name="search_exported_function_in_project")
    def search_exported_function_in_project(self, function_name: str, match: str = "exact", offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Find specific exported functions across the entire project.

        Use this tool to locate where a particular function is exported (e.g., 'DllRegisterServer').
        This is useful for identifying entry points in DLLs or shared objects.

        Args:
            function_name: The name of the exported function to find.
            match: The matching strategy. Options: 'exact' (default), 'contains', 'regex'.
            offset: The starting index for pagination.
            limit: The maximum number of matches to return (max 50).

        Returns:
            list: A list of matches, each containing 'binary', 'export', and 'address'.
        """
        match = (match or "exact").lower()
        offset = max(0, offset)
        limit = min(500, max(1, limit))
        
        hits = []
        for b in self.project_store.list_binaries():
            found_exports = []
            if match == "exact":
                found_exports = b.list_exports(name=function_name, limit=500)
            elif match == "contains":
                found_exports = b.list_exports(query=function_name, limit=500)
            else:
                # Regex support: fetch all exports (limit=10000) and filter
                all_exports = b.list_exports(limit=10000)
                for ex in all_exports:
                    name = ex.get("name") or ""
                    try:
                        if re.search(function_name, name):
                            found_exports.append(ex)
                    except Exception:
                        pass
            
            for ex in found_exports:
                hits.append({"binary": b.display_name, "export": ex})
                
        return hits[offset : offset + limit]

    def _maybe_parse_json(self, value):
        if not isinstance(value, str):
            return value
        s = value.strip()
        if not s:
            return value
        if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
            try:
                return json.loads(s)
            except Exception:
                return value
        return value

    def _coerce_json_list(self, value):
        v = self._maybe_parse_json(value)
        if isinstance(v, list):
            return v
        if isinstance(v, tuple):
            return list(v)
        if isinstance(v, str) and "," in v:
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @mcp_tool(name="audit_create_note")
    def audit_create_note(self, binary_name: str, content: str, note_type: str,
                          title: str = None, function_name: str = None, address = None,
                          tags: str = None, confidence: str = "medium") -> Dict[str, Any]:
        """Create a new analysis note.

        Args:
            binary_name: The binary file name this note is associated with.
            content: The note content (analysis findings, observations, etc.).
            note_type: Type of note. Options: vulnerability, behavior, function_summary,
                       data_structure, control_flow, crypto_usage, obfuscation, io_operation, general.
            title: Optional title for the note.
            function_name: Optional function name to associate with this note.
            address: Optional virtual address (hex or int) to associate with this note.
            tags: Optional comma-separated list of tags.
            confidence: Confidence level. Options: high, medium, low, speculative. Default: medium.

        Returns:
            dict: Contains note_id of the created note.
        """
        return audit_mcp_tools.audit_create_note(
            binary_name=binary_name,
            content=content,
            note_type=note_type,
            title=title,
            function_name=function_name,
            address=address,
            tags=tags,
            confidence=confidence
        )

    @mcp_tool(name="audit_get_notes")
    def audit_get_notes(self, binary_name: str = None, query: str = None,
                        note_type: str = None, tags: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Query analysis notes.

        Args:
            binary_name: Optional binary name to filter by.
            query: Optional search term to match in note content.
            note_type: Optional note type filter.
            tags: Optional comma-separated tags to filter by.
            limit: Maximum number of notes to return. Default: 50.

        Returns:
            list: Array of note objects with note_id, binary_name, function_name, address,
                  note_type, content, confidence, tags, created_at, updated_at.
        """
        return audit_mcp_tools.audit_get_notes(
            binary_name=binary_name,
            query=query,
            note_type=note_type,
            tags=tags,
            limit=limit
        )

    @mcp_tool(name="audit_update_note")
    def audit_update_note(self, note_id: int, content: str = None, title: str = None, tags: str = None) -> Dict[str, Any]:
        """Update an existing note's content or tags.

        Args:
            note_id: The ID of the note to update.
            content: Optional new content for the note.
            title: Optional new title for the note.
            tags: Optional comma-separated list of new tags.

        Returns:
            dict: Contains success boolean.
        """
        return audit_mcp_tools.audit_update_note(
            note_id=note_id,
            content=content,
            title=title,
            tags=tags
        )

    @mcp_tool(name="audit_delete_note")
    def audit_delete_note(self, note_id: int) -> Dict[str, Any]:
        """Delete a note.

        Args:
            note_id: The ID of the note to delete.

        Returns:
            dict: Contains success boolean.
        """
        return audit_mcp_tools.audit_delete_note(note_id=note_id)

    @mcp_tool(name="audit_report_vulnerability")
    def audit_report_vulnerability(self, binary_name: str, severity: str, category: str, title: str, description: str,
                           function_name: str = None, address = None,
                           evidence: str = None, cvss: float = None,
                           exploitability: str = None) -> Dict[str, Any]:
        """Report a confirmed or suspected security vulnerability.

        Use this tool ONLY for reporting significant security issues (e.g., buffer overflows, logic flaws, hardcoded secrets).
        Do NOT use this for general observations or code quality issues (use `audit_create_note` for those).

        Args:
            binary_name: The binary file name this vulnerability is associated with.
            severity: Vulnerability severity. Options: critical, high, medium, low, info.
            category: Vulnerability category. Options: buffer_overflow, format_string, integer_overflow,
                      use_after_free, double_free, memory_disclosure, crypto_weak, hardcoded_secret,
                      injection, path_traversal, authentication, authorization, anti_debug, anti_vm,
                      packing, other.
            title: Short title for the vulnerability.
            description: Detailed description of the vulnerability.
            function_name: Optional function name associated with this vulnerability.
            address: Optional virtual address (hex or int) associated with this vulnerability.
            evidence: Optional evidence or code snippet supporting the vulnerability.
            cvss: Optional CVSS score (0.0-10.0).
            exploitability: Optional exploitability assessment.

        Returns:
            dict: Contains vulnerability_id.
        """
        return audit_mcp_tools.audit_report_vulnerability(
            binary_name=binary_name,
            severity=severity,
            category=category,
            title=title,
            description=description,
            function_name=function_name,
            address=address,
            evidence=evidence,
            cvss=cvss,
            exploitability=exploitability
        )

    @mcp_tool(name="audit_get_vulnerabilities")
    def audit_get_vulnerabilities(self, binary_name: str = None, severity: str = None,
                           category: str = None, verification_status: str = None) -> List[Dict[str, Any]]:
        """Query reported security vulnerabilities.

        Args:
            binary_name: Optional binary name to filter by.
            severity: Optional severity filter. Options: critical, high, medium, low, info.
            category: Optional category filter. Options: buffer_overflow, format_string, integer_overflow, etc.
            verification_status: Optional verification status filter. Options: unverified, confirmed, false_positive, needs_review, inconclusive.

        Returns:
            list: Array of vulnerability objects with vulnerability_id, binary_name, function_name,
                  address, severity, category, description, evidence, cvss, exploitability, created_at, verification_status.
        """
        return audit_mcp_tools.audit_get_vulnerabilities(
            binary_name=binary_name,
            severity=severity,
            category=category,
            verification_status=verification_status
        )

    @mcp_tool(name="audit_get_analysis_progress")
    def audit_get_analysis_progress(self, binary_name: str) -> Dict[str, Any]:
        """Get analysis progress statistics for a binary.

        Args:
            binary_name: The binary file name to get statistics for.

        Returns:
            dict: Contains binary_name, total_notes, notes_by_type, findings_count, findings_by_severity.
        """
        return audit_mcp_tools.audit_get_analysis_progress(binary_name=binary_name)

    # --- Audit Management Tools ---

    @mcp_tool(name="audit_create_macro_plan")
    def audit_create_macro_plan(self, title: str, description: str, parent_id: Optional[int] = None) -> Dict[str, Any]:
        """Create a high-level macro audit plan.
        
        Use this for structural, phased planning (e.g., 'Reconnaissance', 'Auth Module Analysis').
        
        Args:
            title: The title of the macro plan.
            description: Detailed description of the audit phase.
            parent_id: Optional parent macro plan ID (for nesting).

        Returns:
            dict: Contains 'plan_id' of the created plan.
        """
        return audit_mcp_tools.audit_create_macro_plan(title, description, parent_id)

    @mcp_tool(name="audit_create_agent_task")
    def audit_create_agent_task(self, title: str, description: str, parent_plan_id: int, binary_name: str) -> Dict[str, Any]:
        """Create a specific executable task for the Audit Agent.
        
        Use this for assigning concrete work (e.g., 'Analyze login() function').
        MUST be linked to a parent Macro Plan.
        
        Args:
            title: The title of the task.
            description: Specific instructions for the agent (function name, address, goal).
            parent_plan_id: The ID of the parent Macro Plan this task belongs to.
            binary_name: The name of the binary to analyze.

        Returns:
            dict: Contains 'plan_id' of the created task.
        """
        return audit_mcp_tools.audit_create_agent_task(title, description, parent_plan_id, binary_name)

    @mcp_tool(name="audit_create_verification_task")
    def audit_create_verification_task(self, title: str, description: str, parent_plan_id: int, binary_name: str) -> Dict[str, Any]:
        """Create a verification task for a specific finding.
        
        Use this to create a task specifically for verifying a suspected vulnerability (finding).
        MUST be linked to a parent Macro Plan.
        
        Args:
            title: The title of the verification task.
            description: Detailed instructions for verification (e.g., 'Construct PoC for buffer overflow').
            parent_plan_id: The ID of the parent Macro Plan.
            binary_name: The name of the binary.

        Returns:
            dict: Contains 'plan_id' of the created task and 'type'='verification_plan'.
        """
        return audit_mcp_tools.audit_create_verification_task(title, description, parent_plan_id, binary_name)

    @mcp_tool(name="audit_submit_summary")
    def audit_submit_summary(self, plan_id: int, summary: str) -> Dict[str, Any]:
        """Submit a final summary for a completed task.
        
        Use this to record the final outcome, key findings, and conclusion of the task.
        This should be called BEFORE marking the task as completed.

        Args:
            plan_id: The ID of the task.
            summary: The summary text.

        Returns:
            dict: Contains 'success' boolean.
        """
        return audit_mcp_tools.audit_submit_summary(plan_id, summary)

    @mcp_tool(name="audit_get_summary")
    def audit_get_summary(self, plan_id: int) -> Dict[str, Any]:
        """Get the summary of a plan task.

        Args:
            plan_id: The ID of the task.

        Returns:
            dict: Contains 'summary' text.
        """
        return audit_mcp_tools.audit_get_summary(plan_id)

    @mcp_tool(name="audit_plan_list")
    def audit_plan_list(self, status: str = None, plan_type: str = None) -> List[Dict[str, Any]]:
        """List audit plans or agent tasks.
        
        Args:
            status: Filter by status ('pending', 'in_progress', 'completed', 'failed').
            plan_type: Filter by type ('audit_plan' for macro, 'agent_plan' for tasks, 'verification_plan' for verification tasks).

        Returns:
            list: List of plan objects.
        """
        return audit_mcp_tools.audit_plan_list(status, plan_type)

    @mcp_tool(name="audit_delete_plan")
    def audit_delete_plan(self, plan_id: int) -> Dict[str, Any]:
        """Delete an audit plan and its associated data.

        Args:
            plan_id: The ID of the plan to delete.

        Returns:
            dict: Contains 'success' boolean.
        """
        return audit_mcp_tools.audit_delete_plan(plan_id)

    @mcp_tool(name="audit_update_vulnerability_verification")
    def audit_update_vulnerability_verification(self, id: int, status: str, details: str = None) -> Dict[str, Any]:
        """Update the verification status of a vulnerability.

        Args:
            id: The ID of the vulnerability to update.
            status: The new verification status. Options: confirmed, rejected, needs_review, inconclusive.
            details: Optional details or explanation for the verification result.

        Returns:
            dict: Contains 'success' boolean.
        """
        return audit_mcp_tools.audit_update_vulnerability_verification(
            id=id,
            status=status,
            details=details
        )

    def audit_plan_update(self, plan_id: int, notes: str = None) -> Dict[str, Any]:
        """Update the notes of a plan task.
        
        Note: You cannot change the status (pending/in_progress/completed) via this tool.
        Status is managed automatically by the Audit Service.
        Use this tool to add progress notes or findings to a task.

        Args:
            plan_id: The ID of the plan task to update.
            notes: Optional progress notes describing what was done.

        Returns:
            dict: Contains 'success' boolean.
        """
        return audit_mcp_tools.audit_plan_update(plan_id, notes)