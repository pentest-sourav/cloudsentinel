from dataclasses import dataclass
from typing import Any, Callable, Literal


CollectionMode = Literal["single", "multiple"]


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    name: str
    data_source: str
    collection_mode: CollectionMode
    check_arguments: list[str]
    check: Callable[..., Any]
    build_finding: Callable[..., Any]
