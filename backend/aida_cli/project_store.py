import os
import re

from .binary_dbquery import BinaryDbQuery
from .constants import AUDIT_DB_FILENAME


class ProjectStore:
    def __init__(self, project_path):
        self.project_path = os.path.abspath(project_path) if project_path else os.getcwd()
        self.project_id = os.path.basename(self.project_path.rstrip("\\/")) or "default"
        self._binaries = {}
        self._binary_order = []
        self._aliases = {}
        self._load()

    def close(self):
        for b in self._binaries.values():
            try:
                b.close()
            except Exception:
                pass

    def _load(self):
        if os.path.isfile(self.project_path) and self.project_path.lower().endswith(".db"):
            self._add_binary({"db": self.project_path, "display_name": os.path.basename(self.project_path), "role": None})
            return

        if os.path.isdir(self.project_path):
            for fn in sorted(os.listdir(self.project_path)):
                if fn.lower().endswith(".db") and fn != AUDIT_DB_FILENAME:
                    db_path = os.path.join(self.project_path, fn)
                    self._add_binary({"db": db_path, "display_name": fn, "role": None})

    def _add_binary(self, rec):
        db_path = os.path.abspath(rec["db"])
        if not os.path.exists(db_path):
            return
            
        # Try to locate binary path
        binary_path = None
        try:
            dirname = os.path.dirname(db_path)
            basename = os.path.basename(db_path)
            if basename.endswith(".db"):
                for fn in os.listdir(dirname):
                    if fn == basename: continue
                    if basename.startswith(fn + "."):
                        cand = os.path.join(dirname, fn)
                        if os.path.isfile(cand):
                             if binary_path is None or len(cand) > len(binary_path):
                                 binary_path = cand
        except Exception:
            pass

        display_name = rec.get("display_name")
        if binary_path:
            display_name = os.path.basename(binary_path)
        else:
            base_name = os.path.basename(db_path)
            if not display_name or display_name == base_name:
                m = re.match(r"^(?P<name>.+)\.[0-9a-fA-F]{8}\.db$", base_name)
                if m:
                    display_name = m.group("name")
                elif base_name.lower().endswith(".db"):
                    display_name = base_name[:-3]
                else:
                    display_name = base_name

        q = BinaryDbQuery(
            db_path=db_path,
            binary_path=binary_path,
            binary_id=os.path.basename(db_path),
            display_name=display_name,
        )
        meta = {}
        try:
            meta = q.get_metadata_dict()
        except Exception:
            meta = {}
        sha256 = meta.get("sha256") if isinstance(meta, dict) else None
        binary_id = sha256 or os.path.basename(db_path)
        q.binary_id = binary_id
        if binary_id in self._binaries:
            try:
                q.close()
            except Exception:
                pass
            return
        self._binaries[binary_id] = q
        self._binary_order.append(binary_id)
        self._add_alias(q.display_name, binary_id)
        self._add_alias(os.path.basename(db_path), binary_id)

    def _add_alias(self, alias, binary_id):
        if not alias:
            return
        key = str(alias)
        self._aliases.setdefault(key, set()).add(binary_id)
        self._aliases.setdefault(key.lower(), set()).add(binary_id)

    def get_binary(self, binary_name):
        if binary_name is None:
            return None
        key = str(binary_name)
        # Try direct ID lookup first
        b = self._binaries.get(key)
        if b is not None:
            return b
        # Try alias lookup
        candidates = self._aliases.get(key) or self._aliases.get(key.lower())
        if not candidates or len(candidates) != 1:
            return None
        cid = next(iter(candidates))
        return self._binaries.get(cid)

    def list_binaries(self):
        return [self._binaries[i] for i in self._binary_order if i in self._binaries]

    def get_overview(self):
        caps = {}
        bins = self.list_binaries()
        for b in bins:
            for k, v in (b.get_capabilities() or {}).items():
                if v:
                    caps[k] = True
        return {
            "project": self.project_id,
            "binaries_count": len(bins),
            "analysis_status": "ready",
            "backend": "sqlite",
            "capabilities": caps,
        }

    def get_project_binaries(self, offset=None, limit=None, filters=None, detail=False, role=None):
        offset = 0 if offset is None else max(0, int(offset))
        limit = 50 if limit is None else min(500, max(1, int(limit)))
        filters = filters or {}
        out = []
        for b in self.list_binaries():
            summary = b.get_summary()
            # Filter by role if specified
            if role is not None:
                if summary.get("role") != role:
                    continue
            out.append(summary)
        return out[offset : offset + limit]
