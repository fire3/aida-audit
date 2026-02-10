import idautils
import ida_funcs
import idc
import ida_idaapi


class PathFinder:
    """Finds possible call paths from source callers to sink callers."""

    def __init__(self, ruleset, logger):
        self.ruleset = ruleset
        self.logger = logger
        self.source_eas = set()
        self.sink_eas = set()
        self.source_rules = {}  # ea -> rule dict
        self.sink_rules = {}    # ea -> rule dict
        self.badaddr = self._get_badaddr()

    def _get_badaddr(self):
        try:
            import ida_idaapi
            if hasattr(ida_idaapi, "BADADDR"):
                return ida_idaapi.BADADDR
        except ImportError:
            pass
        if idc:
            try:
                return idc.BADADDR
            except:
                pass
        return 0xFFFFFFFFFFFFFFFF

    def _resolve_name(self, name):
        """Resolve a name to an effective address (EA)."""
        if not name:
            return self.badaddr

        # Try exact match
        try:
            ea = idc.get_name_ea_simple(name)
            if ea != self.badaddr:
                return ea
        except Exception:
            pass

        # Try imports
        for prefix in ("_", "__imp_", "__imp__", "."):
            candidate = prefix + name
            try:
                ea = idc.get_name_ea_simple(candidate)
                if ea != self.badaddr:
                    return ea
            except Exception:
                pass
        return self.badaddr

    def _collect_names(self):
        """Collect all names from the binary for matching."""
        name_map = {}
        for ea, name in idautils.Names():
            name_map[name] = ea
            if name.startswith("__imp_"):
                name_map[name[6:]] = ea
            elif name.startswith("_"):
                name_map[name[1:]] = ea
        return name_map

    def _match_rules_against_names(self, rules, name_map, target_set, rule_map):
        """Match a list of rules against the collected names."""
        for rule in rules:
            matched_ea = None

            # 1. Try name match
            name = rule.get("name")
            if name:
                if name in name_map:
                    matched_ea = name_map[name]
                else:
                    matched_ea = self._resolve_name(name)
                    if matched_ea == self.badaddr:
                        matched_ea = None

            # 2. Try regex match
            if not matched_ea and rule.get("regex"):
                regex = rule["regex"]
                for n, ea in name_map.items():
                    if regex.match(n):
                        matched_ea = ea
                        break

            if matched_ea is not None and matched_ea != self.badaddr:
                target_set.add(matched_ea)
                rule_map[matched_ea] = rule
                self.logger.log(f"Matched {rule.get('name') or rule.get('pattern')} @ {hex(matched_ea)}")

    def identify_markers(self):
        """Identify source and sink functions in the binary."""
        self.source_eas = set()
        self.sink_eas = set()
        self.source_rules = {}
        self.sink_rules = {}
        name_map = self._collect_names()
        self._match_rules_against_names(self.ruleset.sources, name_map, self.source_eas, self.source_rules)
        self._match_rules_against_names(self.ruleset.sinks, name_map, self.sink_eas, self.sink_rules)

        self.logger.log(f"Found {len(self.source_eas)} sources and {len(self.sink_eas)} sinks")

    def _get_callers(self, target_eas):
        """Find functions that call any of the target EAs."""
        callers = set()
        for target_ea in target_eas:
            for ref in idautils.CodeRefsTo(target_ea, 0):
                func = ida_funcs.get_func(ref)
                if func:
                    callers.add(func.start_ea)
        return callers

    def _map_callers_to_targets(self, target_eas):
        """Map callers to the target EAs they call."""
        caller_map = {} # caller_ea -> set(target_eas)
        for target_ea in target_eas:
            for ref in idautils.CodeRefsTo(target_ea, 0):
                func = ida_funcs.get_func(ref)
                if func:
                    caller = func.start_ea
                    if caller not in caller_map:
                        caller_map[caller] = set()
                    caller_map[caller].add(target_ea)
        return caller_map

    def _get_callees(self, func_ea):
        """Get all functions called by the given function."""
        func = ida_funcs.get_func(func_ea)
        if not func:
            return set()

        callees = set()
        for head in idautils.Heads(func.start_ea, func.end_ea):
            # 1. Code Refs (Direct calls)
            refs = idautils.CodeRefsFrom(head, 0)
            for ref in refs:
                ref_func = ida_funcs.get_func(ref)
                if ref_func and ref_func.start_ea == ref:
                    callees.add(ref_func.start_ea)

            # 2. Data Refs (Indirect calls via vtables/globals)
            drefs = idautils.DataRefsFrom(head)
            for dref in drefs:
                # Check if the data item refers to a function
                sub_drefs = idautils.DataRefsFrom(dref)
                for sub_dref in sub_drefs:
                    ref_func = ida_funcs.get_func(sub_dref)
                    if ref_func and ref_func.start_ea == sub_dref:
                        callees.add(ref_func.start_ea)
        return callees

    def _bfs_search(self, start_nodes, end_nodes, neighbor_fn=None):
        """Reusable BFS search."""
        if not start_nodes or not end_nodes:
            return []

        if neighbor_fn is None:
            neighbor_fn = self._get_callees

        from collections import deque
        queue = deque([(start, [start]) for start in start_nodes])
        visited = set(start_nodes)
        found_paths = []
        MAX_DEPTH = 100
        MAX_PATHS = 100

        while queue:
            curr_ea, path = queue.popleft()

            if len(path) > MAX_DEPTH:
                continue

            if curr_ea in end_nodes:
                found_paths.append(path)
                if len(found_paths) >= MAX_PATHS:
                    break
                continue

            callees = neighbor_fn(curr_ea)
            for callee in callees:
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))

        return found_paths

    def _get_callers_single(self, func_ea):
        """Get functions that call the given function."""
        callers = set()
        for ref in idautils.CodeRefsTo(func_ea, 0):
            func = ida_funcs.get_func(ref)
            if func:
                callers.add(func.start_ea)
        return callers

    def find_common_ancestors(self, source_callers, sink_callers):
        """Find paths where source and sink share a common ancestor."""
        from collections import deque
        # BFS up from source callers
        source_ancestors = {} # ea -> path_from_source
        queue = deque([(start, [start]) for start in source_callers])
        visited_source = set(source_callers)
        MAX_DEPTH = 10

        while queue:
            curr, path = queue.popleft()
            source_ancestors[curr] = path

            if len(path) > MAX_DEPTH: continue

            callers = self._get_callers_single(curr)
            for caller in callers:
                if caller not in visited_source:
                    visited_source.add(caller)
                    queue.append((caller, path + [caller]))

        # BFS up from sink callers and check intersection
        queue = deque([(start, [start]) for start in sink_callers])
        visited_sink = set(sink_callers)
        common_paths = []

        while queue:
            curr, path = queue.popleft()

            if curr in source_ancestors:
                # Found common ancestor
                src_path = source_ancestors[curr]
                # Combine: [Source, ..., Common, ..., Sink]
                # src_path is [Source, ..., Common]
                # path is [Sink, ..., Common]
                # We want [Source, ..., Common] + [..., Sink]
                # path[-2::-1] reverses path excluding the last element (Common)
                p = src_path + path[-2::-1]
                common_paths.append(p)

            if len(path) > MAX_DEPTH: continue

            callers = self._get_callers_single(curr)
            for caller in callers:
                if caller not in visited_sink:
                    visited_sink.add(caller)
                    queue.append((caller, path + [caller]))

        return common_paths

    def find_paths(self):
        """Find paths from source callers to sink callers using bidirectional search."""
        if not self.source_eas or not self.sink_eas:
            return []

        source_callers = self._get_callers(self.source_eas)
        sink_callers = self._get_callers(self.sink_eas)

        if not source_callers:
            self.logger.log("No callers found for sources")
        if not sink_callers:
            self.logger.log("No callers found for sinks")

        if not source_callers or not sink_callers:
            return []
            
        # Map callers back to their targets for reporting
        source_caller_map = self._map_callers_to_targets(self.source_eas)
        sink_caller_map = self._map_callers_to_targets(self.sink_eas)

        self.logger.log(f"Tracing paths from {len(source_callers)} source callers to {len(sink_callers)} sink callers")

        # 1. Forward: Source Caller -> Sink Caller
        fwd_paths = self._bfs_search(source_callers, sink_callers)
        
        # 2. Reverse: Sink Caller -> Source Caller (Return taint flow)
        rev_paths = self._bfs_search(sink_callers, source_callers)

        # 3. Common Ancestor: SourceCaller <- Common -> SinkCaller
        common_paths = self.find_common_ancestors(source_callers, sink_callers)
        
        all_paths = []
        
        def _build_result(path_nodes):
            if not path_nodes: return None
            
            start_caller = path_nodes[0]
            end_caller = path_nodes[-1]
            
            # Resolve Source Info
            src_info = None
            if start_caller in source_caller_map:
                # Pick the first matching source for this caller
                # In the future, we might want to list all if ambiguous
                src_ea = next(iter(source_caller_map[start_caller]))
                rule = self.source_rules.get(src_ea, {})
                src_info = {
                    "name": rule.get("name"),
                    "ea": hex(src_ea),
                    "args": rule.get("args")
                }
                
            # Resolve Sink Info
            sink_info = None
            if end_caller in sink_caller_map:
                sink_ea = next(iter(sink_caller_map[end_caller]))
                rule = self.sink_rules.get(sink_ea, {})
                sink_info = {
                    "name": rule.get("name"),
                    "ea": hex(sink_ea),
                    "args": rule.get("args")
                }
            
            return {
                "path": self._format_path(path_nodes),
                "source": src_info,
                "sink": sink_info
            }

        for p in fwd_paths:
            res = _build_result(p)
            if res: all_paths.append(res)
            
        for p in rev_paths:
            res = _build_result(p[::-1])
            if res: all_paths.append(res)

        for p in common_paths:
            res = _build_result(p)
            if res: all_paths.append(res)
            
        return all_paths

    def _format_path(self, path):
        """Format the path for output."""
        result = []
        for ea in path:
            name = ida_funcs.get_func_name(ea)
            result.append({"name": name, "ea": hex(ea)})
        return result