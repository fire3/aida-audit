import idautils
import idc
import ida_idaapi

class RuleMatcher:
    def __init__(self, logger=None):
        self.logger = logger
        self.badaddr = self._get_badaddr()

    def _get_badaddr(self):
        try:
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

    def normalize_name(self, name):
        if not name:
            return None
        lowered = name.lower()
        for prefix in ("__imp__", "__imp_", "_", "."):
            if lowered.startswith(prefix):
                lowered = lowered[len(prefix):]
        if "@@" in lowered:
            lowered = lowered.split("@@", 1)[0]
        elif "@" in lowered:
            lowered = lowered.split("@", 1)[0]
        if ".plt" in lowered:
            lowered = lowered.split(".plt", 1)[0]
        return lowered or None

    def resolve_name(self, name):
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

    def resolve_function_ref(self, function_ref):
        if function_ref is None:
            return self.badaddr
        if isinstance(function_ref, int):
            return function_ref
        if not isinstance(function_ref, str):
            return self.badaddr
        value = function_ref.strip()
        if not value:
            return self.badaddr
        try:
            if value.lower().startswith("0x"):
                return int(value, 16)
            if value.isdigit():
                return int(value, 10)
        except Exception:
            return self.badaddr
        resolved = self.resolve_name(value)
        if resolved != self.badaddr:
            return resolved
        normalized = self.normalize_name(value)
        if normalized and normalized != value:
            return self.resolve_name(normalized)
        return self.badaddr

    def collect_names(self):
        """Collect all names from the binary for matching."""
        name_map = {}
        # Check if idautils is available
        if not hasattr(idautils, "Names"):
            return name_map
            
        for ea, name in idautils.Names():
            name_map[name] = ea
            norm = self.normalize_name(name)
            if norm and norm not in name_map:
                name_map[norm] = ea
        return name_map

    def match_rules_against_names(self, rules, name_map, target_set, rule_map):
        """Match a list of rules against the collected names."""
        unmatched = []
        for rule in rules:
            matched_ea = None

            # 1. Try name match
            name = rule.get("name")
            if name:
                norm = self.normalize_name(name)
                if name in name_map:
                    matched_ea = name_map[name]
                elif norm and norm in name_map:
                    matched_ea = name_map[norm]
                else:
                    matched_ea = self.resolve_name(name)
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
                if self.logger:
                    self.logger.log(f"Matched {rule.get('name') or rule.get('pattern')} @ {hex(matched_ea)}")
            else:
                unmatched.append(rule)
        return unmatched
