from collections import deque
from typing import List

from .common import FuncInfo
from .state import TaintState, TaintOrigin
from .microcode_analyzer import analyze_function
from .logger import SimpleLogger
from .fixed_point_engine import FixedPointTaintEngine
from ..pathfinder import PathFinder, PathFinderConfig


class WorklistTaintEngine:
    def __init__(self, ruleset, logger=None, verbose=False):
        self.ruleset = ruleset
        self.logger = logger or SimpleLogger(verbose=verbose)
        self.engine = FixedPointTaintEngine(ruleset, self.logger, verbose)

    def scan_function(self, func_info):
        return self.engine.analyze_function(func_info)

    def scan_global(self, maturity):
        for rule in self.engine.ruleset.sources:
            if "name" in rule:
                ea = self.engine.rule_matcher.resolve_name(rule["name"])
                if ea != self.engine.rule_matcher.badaddr:
                    rule["ea"] = ea
        for rule in self.engine.ruleset.sinks:
            if "name" in rule:
                ea = self.engine.rule_matcher.resolve_name(rule["name"])
                if ea != self.engine.rule_matcher.badaddr:
                    rule["ea"] = ea
        for rule in self.engine.ruleset.propagators:
            if "name" in rule:
                ea = self.engine.rule_matcher.resolve_name(rule["name"])
                if ea != self.engine.rule_matcher.badaddr:
                    rule["ea"] = ea

        self.engine.pathfinder.ruleset = self.ruleset
        self.engine.pathfinder.identify_markers()
        path_result = self.engine.pathfinder.find_paths()

        if not path_result:
            return []

        raw_chains = [p["nodes"] for p in path_result]

        chain_functions = set()
        for path in raw_chains:
            for node in path:
                ea = int(node["ea"], 16)
                chain_functions.add(ea)

        if not chain_functions:
            return []

        chain_functions = sorted(chain_functions, key=lambda x: x)

        findings = []
        from .constants import ida_funcs
        for ea in chain_functions:
            func = ida_funcs.get_func(ea)
            if not func:
                continue

            func_info = analyze_function(func, maturity)
            if func_info:
                state, f_findings = self.engine.analyze_function(func_info)

                real_findings = []
                proxy_findings = []
                for f in f_findings:
                    if hasattr(f, "type") and f.type == "sink_proxy":
                        proxy_findings.append(f)
                    else:
                        labels = f.taint_labels if hasattr(f, "taint_labels") else []
                        has_real = any(not str(label).startswith("SYM:ARG:") for label in labels)
                        if has_real or not labels:
                            real_findings.append(f)

                findings.extend(real_findings)

        for finding in findings:
            if hasattr(finding, "call_chains"):
                finding.call_chains = raw_chains
            else:
                finding.call_chains = raw_chains

        return findings


__all__ = ["WorklistTaintEngine"]