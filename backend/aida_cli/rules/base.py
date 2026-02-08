import networkx as nx
from typing import Iterator, Any, Optional
from ..model import Finding

class BaseRule:
    def match(self, graph: nx.MultiDiGraph) -> Iterator[Any]:
        raise NotImplementedError
    
    def analyze(self, graph: nx.MultiDiGraph, candidate: Any) -> Optional[Finding]:
        raise NotImplementedError
