from dataclasses import dataclass, field
from typing import Optional, Set, Dict, FrozenSet, Tuple
from .common import (
    OperandAttr,
    RegisterAttr,
    LocalVarAttr,
    StackAttr,
    GlobalAttr,
    ImmediateAttr,
    StringAttr,
    AddressAttr,
    LoadAttr,
    ExpressionAttr,
    AttrType,
)


@dataclass(frozen=True)
class TaintOrigin:
    """污点来源信息"""
    label: str
    ea: str
    function: str

    def __lt__(self, other):
        return (self.label, self.ea, self.function) < (other.label, other.ea, other.function)


@dataclass(frozen=True)
class TaintLabel:
    """污点标签 (不可变，便于哈希和比较)"""
    source: str
    name: str

    def __str__(self):
        return f"{self.source}:{self.name}"

    def __lt__(self, other):
        return (self.source, self.name) < (other.source, other.name)


@dataclass
class TaintEntry:
    """单个位置的污点状态"""
    labels: Set[str] = field(default_factory=set)
    origins: Set[TaintOrigin] = field(default_factory=set)
    _last_reason: str = field(default="", init=False, repr=False)

    def is_empty(self) -> bool:
        return not self.labels

    def merge(self, other: "TaintEntry") -> bool:
        changed = False
        new_labels = other.labels - self.labels
        if new_labels:
            self.labels.update(new_labels)
            changed = True
        new_origins = other.origins - self.origins
        if new_origins:
            self.origins.update(new_origins)
            changed = True
        return changed

    def union(self, other: "TaintEntry") -> "TaintEntry":
        return TaintEntry(
            labels=self.labels | other.labels,
            origins=self.origins | other.origins,
        )

    def clone(self) -> "TaintEntry":
        return TaintEntry(
            labels=set(self.labels),
            origins=set(self.origins),
        )


@dataclass
class TaintState:
    """函数内的污点状态"""
    entries: Dict[OperandAttr, TaintEntry] = field(default_factory=dict)
    aliases: Dict[OperandAttr, OperandAttr] = field(default_factory=dict)

    def get_taint(self, attr: Optional[OperandAttr]) -> FrozenSet[str]:
        """获取位置的污点标签"""
        if attr is None:
            return frozenset()

        resolved = self._resolve(attr)
        entry = self.entries.get(resolved)
        if entry:
            return frozenset(entry.labels)
        return frozenset()

    def get_origins(self, attr: Optional[OperandAttr]) -> FrozenSet[TaintOrigin]:
        """获取位置的污点来源"""
        if attr is None:
            return frozenset()

        resolved = self._resolve(attr)
        entry = self.entries.get(resolved)
        if entry:
            return frozenset(entry.origins)
        return frozenset()

    def _resolve(self, attr: OperandAttr) -> OperandAttr:
        """解析 LoadAttr，获取最终指向的位置"""
        if isinstance(attr, LoadAttr):
            visited = set()
            current = attr.ptr
            while isinstance(current, LoadAttr) and current not in visited:
                visited.add(current)
                current = current.ptr
            if current in self.aliases:
                return self.aliases[current]
            return current
        if attr in self.aliases:
            return self.aliases[attr]
        return attr

    def add_alias(self, ptr: OperandAttr, target: OperandAttr) -> bool:
        """添加指针别名 ptr -> target，返回是否新增别名"""
        if ptr is None or target is None:
            return False
        if ptr == target:
            return False
        existing = self.aliases.get(ptr)
        if existing != target:
            self.aliases[ptr] = target
            return True
        return False

    def add_taint(self, attr: Optional[OperandAttr], labels: Set[str], origins: Set[TaintOrigin], reason: str = "") -> bool:
        """添加污点，返回是否有变化"""
        if attr is None:
            return False

        resolved = self._resolve(attr)
        entry = self.entries.get(resolved)
        if entry is None:
            entry = TaintEntry()
            self.entries[resolved] = entry

        changed = bool(entry.labels - labels or entry.origins - origins)
        entry.labels.update(labels)
        entry.origins.update(origins)
        if changed:
            entry._last_reason = reason
        return changed

    def add_taint_to(self, attr: OperandAttr, labels: Set[str], origins: Set[TaintOrigin]) -> bool:
        """直接添加污点到指定位置（不解析 load）"""
        entry = self.entries.get(attr)
        if entry is None:
            entry = TaintEntry()
            self.entries[attr] = entry

        changed = bool(entry.labels - labels or entry.origins - origins)
        entry.labels.update(labels)
        entry.origins.update(origins)
        return changed

    def merge(self, other: "TaintState") -> bool:
        """合并另一个状态到当前状态，返回是否有变化 (用于 CFG 合并)"""
        changed = False

        for attr, other_entry in other.entries.items():
            if attr in self.entries:
                if self.entries[attr].merge(other_entry):
                    changed = True
            else:
                self.entries[attr] = other_entry.clone()
                if not other_entry.is_empty():
                    changed = True

        for ptr, target in other.aliases.items():
            if self.aliases.get(ptr) != target:
                self.aliases[ptr] = target
                changed = True

        return changed

    def clone(self) -> "TaintState":
        """深拷贝当前状态 (用于工作列表迭代保存历史)"""
        cloned = TaintState()
        for attr, entry in self.entries.items():
            cloned.entries[attr] = entry.clone()
        cloned.aliases = dict(self.aliases)
        return cloned

    def is_empty(self) -> bool:
        return not self.entries

    def __bool__(self):
        return self.is_empty()

    def __repr__(self) -> str:
        lines = []
        lines.append(f"TaintState(entries={len(self.entries)}, aliases={len(self.aliases)})")
        for attr, entry in self.entries.items():
            if entry.labels:
                reason = f" (reason: {entry._last_reason})" if entry._last_reason else ""
                lines.append(f"  {attr}: labels={sorted(entry.labels)}, origins={len(entry.origins)}{reason}")
        for ptr, target in self.aliases.items():
            lines.append(f"  alias: {ptr} -> {target}")
        return "\n".join(lines) if lines else "TaintState()"