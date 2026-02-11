import hashlib
import time
from dataclasses import dataclass, field

import idautils
import ida_funcs
import idc
import ida_idaapi

from .rule_matcher import RuleMatcher


@dataclass
class PathFinderConfig:
    max_depth: int = 100
    max_paths: int = 100
    ancestor_max_depth: int = 10
    enable_indirect_call: bool = True
    strategies: list = field(default_factory=lambda: ["forward", "reverse", "common_ancestor"])


@dataclass
class SearchStats:
    source_funcs_found: int = 0
    sink_funcs_found: int = 0
    source_callers_found: int = 0
    sink_callers_found: int = 0
    paths_forward: int = 0
    paths_reverse: int = 0
    paths_ancestor: int = 0
    paths_total: int = 0
    nodes_visited: int = 0
    search_time_ms: int = 0


@dataclass
class SearchError:
    level: str
    stage: str
    message: str


class PathSearchResult(list):
    def __init__(self, paths, stats, errors):
        super().__init__(paths)
        self.paths = paths
        self.stats = stats
        self.errors = errors

    def to_payload(self):
        return {
            "paths": list(self),
            "stats": self.stats.__dict__,
            "errors": [e.__dict__ for e in self.errors],
        }


class PathFinder:
    """Finds possible call paths from source callers to sink callers."""

    def __init__(self, ruleset, logger, config=None):
        self.ruleset = ruleset
        self.logger = logger
        self.config = config or PathFinderConfig()
        self.source_eas = set()
        self.sink_eas = set()
        self.source_rules = {}
        self.sink_rules = {}
        self.source_caller_map = {}
        self.sink_caller_map = {}
        self.errors = []
        self.stats = SearchStats()
        self.nodes_visited = 0
        self.matcher = RuleMatcher(logger)

    def _record_error(self, level, stage, message):
        self.errors.append(SearchError(level=level, stage=stage, message=message))
        if level == "warning":
            self.logger.log(message, level="WARN")
        else:
            self.logger.log(message, level="ERROR")

    def identify_markers(self):
        """Identify source and sink functions in the binary."""
        self.source_eas = set()
        self.sink_eas = set()
        self.source_rules = {}
        self.sink_rules = {}
        self.errors = []
        self.stats = SearchStats()
        name_map = self.matcher.collect_names()
        unmatched_sources = self.matcher.match_rules_against_names(self.ruleset.sources, name_map, self.source_eas, self.source_rules)
        unmatched_sinks = self.matcher.match_rules_against_names(self.ruleset.sinks, name_map, self.sink_eas, self.sink_rules)
        for rule in unmatched_sources:
            self._record_error("warning", "marker_identification", f"No match for source rule: {rule.get('name') or rule.get('pattern')}")
        for rule in unmatched_sinks:
            self._record_error("warning", "marker_identification", f"No match for sink rule: {rule.get('name') or rule.get('pattern')}")

        self.logger.log(f"Found {len(self.source_eas)} sources and {len(self.sink_eas)} sinks")
        self.stats.source_funcs_found = len(self.source_eas)
        self.stats.sink_funcs_found = len(self.sink_eas)

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
            return []

        callee_flags = {}
        for head in idautils.Heads(func.start_ea, func.end_ea):
            refs = idautils.CodeRefsFrom(head, 0)
            for ref in refs:
                ref_func = ida_funcs.get_func(ref)
                if ref_func and ref_func.start_ea == ref:
                    callee = ref_func.start_ea
                    callee_flags[callee] = callee_flags.get(callee, False)

            if self.config.enable_indirect_call:
                drefs = idautils.DataRefsFrom(head)
                for dref in drefs:
                    sub_drefs = idautils.DataRefsFrom(dref)
                    for sub_dref in sub_drefs:
                        ref_func = ida_funcs.get_func(sub_dref)
                        if ref_func and ref_func.start_ea == sub_dref:
                            callee = ref_func.start_ea
                            callee_flags[callee] = True
        return [(ea, is_indirect) for ea, is_indirect in callee_flags.items()]

    def _bfs_search(self, start_nodes, end_nodes, neighbor_fn=None):
        """Reusable BFS search."""
        if not start_nodes or not end_nodes:
            return []

        if neighbor_fn is None:
            neighbor_fn = self._get_callees

        from collections import deque
        queue = deque([(start, [start], False) for start in start_nodes])
        visited = set(start_nodes)
        found_paths = []

        while queue:
            curr_ea, path, has_indirect = queue.popleft()
            self.nodes_visited += 1

            if len(path) > self.config.max_depth:
                continue

            if curr_ea in end_nodes:
                found_paths.append((path, has_indirect))
                if len(found_paths) >= self.config.max_paths:
                    break
                continue

            callees = neighbor_fn(curr_ea)
            for callee, is_indirect in callees:
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee], has_indirect or is_indirect))

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
        source_ancestors = {}
        queue = deque([(start, [start]) for start in source_callers])
        visited_source = set(source_callers)

        while queue:
            curr, path = queue.popleft()
            self.nodes_visited += 1
            source_ancestors[curr] = path

            if len(path) > self.config.ancestor_max_depth:
                continue

            callers = self._get_callers_single(curr)
            for caller in callers:
                if caller not in visited_source:
                    visited_source.add(caller)
                    queue.append((caller, path + [caller]))

        queue = deque([(start, [start]) for start in sink_callers])
        visited_sink = set(sink_callers)
        common_paths = []

        while queue:
            curr, path = queue.popleft()
            self.nodes_visited += 1

            if curr in source_ancestors:
                src_path = source_ancestors[curr]
                p = src_path + path[-2::-1]
                common_paths.append((p, curr))

            if len(path) > self.config.ancestor_max_depth:
                continue

            callers = self._get_callers_single(curr)
            for caller in callers:
                if caller not in visited_sink:
                    visited_sink.add(caller)
                    queue.append((caller, path + [caller]))

        return common_paths

    def _hash_path(self, path_nodes):
        data = ",".join(hex(ea) for ea in path_nodes).encode("utf-8")
        return hashlib.sha1(data).hexdigest()

    def _build_result(self, path_nodes, has_indirect, strategy, ancestor_ea=None):
        if not path_nodes:
            return None

        start_caller = path_nodes[0]
        end_caller = path_nodes[-1]

        src_info = None
        if start_caller in self.source_caller_map:
            src_ea = next(iter(self.source_caller_map[start_caller]))
            rule = self.source_rules.get(src_ea, {})
            src_info = {
                "name": ida_funcs.get_func_name(src_ea),
                "ea": hex(src_ea),
                "args": rule.get("args"),
            }

        sink_info = None
        if end_caller in self.sink_caller_map:
            sink_ea = next(iter(self.sink_caller_map[end_caller]))
            rule = self.sink_rules.get(sink_ea, {})
            sink_info = {
                "name": ida_funcs.get_func_name(sink_ea),
                "ea": hex(sink_ea),
                "args": rule.get("args"),
            }

        nodes = self._format_nodes(path_nodes, strategy, ancestor_ea)
        return {
            "path_id": self._hash_path(path_nodes),
            "nodes": nodes,
            "source": src_info,
            "sink": sink_info,
            "strategy": strategy,
            "depth": len(path_nodes),
            "has_indirect": has_indirect,
        }

    def _aggregate_results(self, fwd_results, rev_results, ancestor_results):
        seen = set()
        merged = []
        for results in (fwd_results, rev_results, ancestor_results):
            for result in results:
                key = result.get("path_id")
                if key not in seen:
                    seen.add(key)
                    merged.append(result)
        merged.sort(key=lambda r: len(r.get("nodes", [])))
        return merged

    def find_paths(self):
        """
        Find paths from source callers to sink callers using bidirectional search.

        Returns:
            list: List of path objects in JSON format. Each path object contains:
                - nodes (list): List of function nodes from source to sink.
                    Each node is a dict with:
                        - name (str): Function name
                        - ea (str): Function address in hex (e.g., "0x401000")
                        - roles (list): Role tags for this node within the path
                - source (dict): Source function information or None.
                    Contains:
                        - name (str): Source rule name
                        - ea (str): Source address in hex
                        - args (list): Source arguments if specified in rule
                - sink (dict): Sink function information or None.
                    Contains:
                        - name (str): Sink rule name
                        - ea (str): Sink address in hex
                        - args (list): Sink arguments if specified in rule

            Example return value:
            [
                {
                    "nodes": [
                        {"name": "main", "ea": "0x401000", "roles": ["source_caller"]},
                        {"name": "process_input", "ea": "0x401100", "roles": ["intermediate"]},
                        {"name": "write_file", "ea": "0x401200", "roles": ["sink_caller"]}
                    ],
                    "source": {"name": "get_user_input", "ea": "0x405000", "args": [0]},
                    "sink": {"name": "fopen", "ea": "0x406000", "args": [0, 1]}
                }
            ]
        """
        start_time = time.time()
        self.nodes_visited = 0
        if not self.source_eas or not self.sink_eas:
            self._record_error("warning", "path_search", "No source or sink markers identified")
            return PathSearchResult([], self.stats, self.errors)

        source_callers = self._get_callers(self.source_eas)
        sink_callers = self._get_callers(self.sink_eas)
        self.stats.source_callers_found = len(source_callers)
        self.stats.sink_callers_found = len(sink_callers)

        if not source_callers:
            self._record_error("warning", "caller_resolution", "No callers found for sources")
        if not sink_callers:
            self._record_error("warning", "caller_resolution", "No callers found for sinks")

        if not source_callers or not sink_callers:
            return PathSearchResult([], self.stats, self.errors)
            
        self.source_caller_map = self._map_callers_to_targets(self.source_eas)
        self.sink_caller_map = self._map_callers_to_targets(self.sink_eas)

        self.logger.log(f"Tracing paths from {len(source_callers)} source callers to {len(sink_callers)} sink callers")

        strategies = set(self.config.strategies or [])
        fwd_results = []
        rev_results = []
        ancestor_results = []

        if "forward" in strategies:
            fwd_paths = self._bfs_search(source_callers, sink_callers)
            for path_nodes, has_indirect in fwd_paths:
                res = self._build_result(path_nodes, has_indirect, "forward")
                if res:
                    fwd_results.append(res)

        if "reverse" in strategies:
            rev_paths = self._bfs_search(sink_callers, source_callers)
            for path_nodes, has_indirect in rev_paths:
                res = self._build_result(path_nodes[::-1], has_indirect, "reverse")
                if res:
                    rev_results.append(res)

        if "common_ancestor" in strategies:
            common_paths = self.find_common_ancestors(source_callers, sink_callers)
            for path_nodes, ancestor_ea in common_paths:
                res = self._build_result(path_nodes, False, "common_ancestor", ancestor_ea=ancestor_ea)
                if res:
                    ancestor_results.append(res)

        self.stats.paths_forward = len(fwd_results)
        self.stats.paths_reverse = len(rev_results)
        self.stats.paths_ancestor = len(ancestor_results)
        merged = self._aggregate_results(fwd_results, rev_results, ancestor_results)
        self.stats.paths_total = len(merged)
        self.stats.nodes_visited = self.nodes_visited
        self.stats.search_time_ms = int((time.time() - start_time) * 1000)
        return PathSearchResult(merged, self.stats, self.errors)

    def _format_nodes(self, path_nodes, strategy, ancestor_ea):
        if not path_nodes:
            return []

        source_caller = path_nodes[0]
        sink_caller = path_nodes[-1]
        ordered_nodes = path_nodes
        if strategy == "common_ancestor" and ancestor_ea in path_nodes:
            ancestor_index = path_nodes.index(ancestor_ea)
            source_part = path_nodes[:ancestor_index]
            sink_part = path_nodes[ancestor_index + 1 :]
            ordered_nodes = [ancestor_ea] + source_part + sink_part

        unique_nodes = []
        seen = set()
        for ea in ordered_nodes:
            if ea in seen:
                continue
            seen.add(ea)
            unique_nodes.append(ea)

        nodes = []
        for ea in unique_nodes:
            roles = []
            if ea == source_caller:
                roles.append("source_caller")
            if ea == sink_caller:
                roles.append("sink_caller")
            if strategy == "common_ancestor" and ancestor_ea is not None and ea == ancestor_ea:
                roles.append("common_ancestor")
            if not roles:
                roles.append("intermediate")
            nodes.append({"name": ida_funcs.get_func_name(ea), "ea": hex(ea), "roles": roles})
        return nodes
