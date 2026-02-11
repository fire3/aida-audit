from .constants import BADADDR


class TaintState:
    def __init__(self):
        self.taint = {}
        self.origins = {}
        self.aliases = {}

    def get_taint(self, key):
        if not key:
            return set()

        if key.startswith("load:"):
            ptr_key = key[5:]
            if ptr_key in self.aliases:
                target = self.aliases[ptr_key]
                return self.get_taint(target)

        labels = self.taint.get(key, set())
        if not labels and key in self.aliases:
            target = self.aliases[key]
            labels = self.taint.get(target, set())
        return labels

    def get_origins(self, key):
        if not key:
            return set()

        if key.startswith("load:"):
            ptr_key = key[5:]
            if ptr_key in self.aliases:
                target = self.aliases[ptr_key]
                return self.get_origins(target)

        origins = self.origins.get(key, set())
        if not origins and key in self.aliases:
            target = self.aliases[key]
            origins = self.origins.get(target, set())
        return origins

    def add_alias(self, ptr, target):
        if ptr and target and ptr != target:
            self.aliases[ptr] = target

    def add_taint(self, key, labels, origins):
        if not key:
            return
        existing = self.taint.setdefault(key, set())
        existing.update(labels)
        if origins:
            origin_set = self.origins.setdefault(key, set())
            origin_set.update(origins)