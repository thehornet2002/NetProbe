import time
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any


@dataclass
class TestResult:
    __test__ = False
    scenario_id: str
    name: str
    category: str
    field_tested: str
    original_val: str
    mutated_val: str
    direction: str
    attempts_used: int
    rtt_ms: float
    response_status: str
    peer_response_flags: str
    details: str
    timestamp: float = 0.0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseScenario:
    """Base class for all NetProbe test scenarios."""

    scenario_id: str = "BASE"
    name: str = "Base Scenario"
    category: str = "GENERIC"
    field_tested: str = "None"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        raise NotImplementedError
