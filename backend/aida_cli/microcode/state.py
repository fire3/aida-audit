from dataclasses import dataclass, field
from typing import Optional, Set, Dict, FrozenSet, Tuple
from .constants import BADADDR


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
    source: str          # 来源类型: "SOURCE", "ARG", "DERIVED"
    name: str            # 具体名称

    def __str__(self):
        return f"{self.source}:{self.name}"

    def __lt__(self, other):
        return (self.source, self.name) < (other.source, other.name)


@dataclass
class TaintEntry:
    """
    单个位置的污点状态

    Attributes:
        labels: 污点标签集合 (如 {"SOURCE:printf", "ARG:0"})
        origins: 来源信息集合，用于追踪污点路径
    """
    labels: Set[str] = field(default_factory=set)
    origins: Set[TaintOrigin] = field(default_factory=set)

    def is_empty(self) -> bool:
        return not self.labels

    def merge(self, other: "TaintEntry") -> bool:
        """合并另一个污点条目，返回是否有新污点添加"""
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
        """返回两者的并集"""
        return TaintEntry(
            labels=self.labels | other.labels,
            origins=self.origins | other.origins,
        )

    def clone(self) -> "TaintEntry":
        """深拷贝"""
        return TaintEntry(
            labels=set(self.labels),
            origins=set(self.origins),
        )


@dataclass
class TaintState:
    """
    函数内的污点状态

    支持不动点迭代所需的操作:
    - clone(): 保存历史状态
    - merge(): CFG 节点合并
    - is_changed(): 检测收敛

    Key 格式:
        - "reg:{name}"      - 寄存器，如 "reg:eax"
        - "imm:{value}"     - 立即数
        - "addr:{ea}"       - 内存地址，如 "addr:0x401000"
        - "lvar:{idx}"      - 局部变量，如 "lvar:0"
        - "stack:{offset}"  - 栈偏移，如 "stack:-8"
        - "load:{key}"      - 指针解引用，如 "load:reg:ptr"
        - "arg:{idx}"       - 函数参数
    """
    entries: Dict[str, TaintEntry] = field(default_factory=dict)
    aliases: Dict[str, str] = field(default_factory=dict)

    def get_taint(self, key: str) -> FrozenSet[str]:
        """获取位置的污点标签"""
        if not key:
            return frozenset()

        if key.startswith("load:"):
            ptr_key = key[5:]
            return self._resolve_load(ptr_key)

        entry = self.entries.get(key)
        if entry:
            return frozenset(entry.labels)
        return frozenset()

    def _resolve_load(self, ptr_key: str) -> FrozenSet[str]:
        """解析 load 操作：跟随指针链直到找到实际污点"""
        visited = set()
        current = ptr_key

        while current in self.aliases and current not in visited:
            visited.add(current)
            current = self.aliases[current]

        if current in self.entries:
            return frozenset(self.entries[current].labels)
        return frozenset()

    def get_origins(self, key: str) -> FrozenSet[TaintOrigin]:
        """获取位置的污点来源"""
        if not key:
            return frozenset()

        if key.startswith("load:"):
            ptr_key = key[5:]
            return self._resolve_load_origins(ptr_key)

        entry = self.entries.get(key)
        if entry:
            return frozenset(entry.origins)
        return frozenset()

    def _resolve_load_origins(self, ptr_key: str) -> FrozenSet[TaintOrigin]:
        """解析 load 操作的来源"""
        visited = set()
        current = ptr_key

        while current in self.aliases and current not in visited:
            visited.add(current)
            current = self.aliases[current]

        if current in self.entries:
            return frozenset(self.entries[current].origins)
        return frozenset()

    def add_alias(self, ptr: str, target: str) -> bool:
        """添加指针别名 ptr -> target，返回是否新增别名"""
        if ptr and target and ptr != target:
            if self.aliases.get(ptr) != target:
                self.aliases[ptr] = target
                return True
        return False

    def add_taint(self, key: str, labels: Set[str], origins: Set[TaintOrigin]) -> bool:
        """添加污点，返回是否有变化"""
        if not key:
            return False

        entry = self.entries.get(key)
        if entry is None:
            entry = TaintEntry()
            self.entries[key] = entry

        changed = bool(entry.labels - labels or entry.origins - origins)
        entry.labels.update(labels)
        entry.origins.update(origins)
        return changed

    def merge(self, other: "TaintState") -> bool:
        """合并另一个状态到当前状态，返回是否有变化 (用于 CFG 合并)"""
        changed = False

        for key, other_entry in other.entries.items():
            if key in self.entries:
                if self.entries[key].merge(other_entry):
                    changed = True
            else:
                self.entries[key] = other_entry.clone()
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
        for key, entry in self.entries.items():
            cloned.entries[key] = entry.clone()
        cloned.aliases = dict(self.aliases)
        return cloned

    def is_empty(self) -> bool:
        """检查是否没有任何污点"""
        return not self.entries or all(e.is_empty() for e in self.entries.values())

    def __eq__(self, other: object) -> bool:
        """状态相等比较 (用于不动点检测)"""
        if not isinstance(other, TaintState):
            return False
        if self.entries.keys() != other.entries.keys():
            return False
        if self.aliases != other.aliases:
            return False
        for key in self.entries:
            if self.entries[key].labels != other.entries[key].labels:
                return False
        return True

    def __hash__(self) -> int:
        """允许在 frozenset 中使用"""
        return hash((
            frozenset((k, frozenset(v.labels)) for k, v in self.entries.items()),
            frozenset(self.aliases.items())
        ))

    def __repr__(self) -> str:
        """用于调试的字符串表示"""
        lines = []
        if self.entries:
            lines.append("Taint entries:")
            for key, entry in self.entries.items():
                if entry.labels:
                    lines.append(f"  {key}: labels={sorted(entry.labels)}")
        if self.aliases:
            lines.append(f"Aliases: {dict(self.aliases)}")
        return "\n".join(lines) if lines else "TaintState(empty)"

    def dump(self, indent: int = 0) -> str:
        """详细打印taint state"""
        prefix = "  " * indent
        lines = [f"{prefix}TaintState:"]
        
        if self.entries:
            lines.append(f"{prefix}  Entries ({len(self.entries)}):")
            for key, entry in sorted(self.entries.items()):
                if entry.labels or entry.origins:
                    labels_str = ", ".join(sorted(entry.labels)) if entry.labels else "(none)"
                    origins_str = ", ".join(f"{o.label}@{o.ea}" for o in sorted(entry.origins)) if entry.origins else "(none)"
                    lines.append(f"{prefix}    {key}:")
                    lines.append(f"{prefix}      labels: [{labels_str}]")
                    lines.append(f"{prefix}      origins: [{origins_str}]")
        
        if self.aliases:
            lines.append(f"{prefix}  Aliases ({len(self.aliases)}):")
            for ptr, target in sorted(self.aliases.items()):
                lines.append(f"{prefix}    {ptr} -> {target}")
        
        return "\n".join(lines) if lines else f"{prefix}TaintState: (empty)"