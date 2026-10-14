from typing import List, Dict, Any
from netprobe.scenarios.base import TestResult


class ReportCollector:
    """Aggregates test results and generates summary statistics."""

    def __init__(self):
        self.results: List[TestResult] = []

    def add_result(self, result: TestResult):
        self.results.append(result)

    def get_summary(self) -> Dict[str, Any]:
        total = len(self.results)
        if total == 0:
            return {
                "total": 0,
                "success": 0,
                "rejected_rst": 0,
                "timeout_drop": 0,
                "retry_exhausted": 0,
                "avg_rtt_ms": 0.0,
                "min_rtt_ms": 0.0,
                "max_rtt_ms": 0.0,
                "categories": {},
                "directions": {},
            }

        delays = [r.rtt_ms for r in self.results if r.rtt_ms > 0]
        avg_rtt = sum(delays) / len(delays) if delays else 0.0
        min_rtt = min(delays) if delays else 0.0
        max_rtt = max(delays) if delays else 0.0

        success = sum(1 for r in self.results if r.response_status == "SUCCESS")
        rejected_rst = sum(1 for r in self.results if r.response_status == "REJECTED_RST")
        retry_exhausted = sum(1 for r in self.results if r.response_status == "RETRY_EXHAUSTED")
        timeout_drop = total - (success + rejected_rst)

        cat_counts = {}
        for r in self.results:
            cat_counts[r.category] = cat_counts.get(r.category, 0) + 1

        dir_counts = {}
        for r in self.results:
            dir_counts[r.direction] = dir_counts.get(r.direction, 0) + 1

        return {
            "total": total,
            "success": success,
            "rejected_rst": rejected_rst,
            "timeout_drop": timeout_drop,
            "retry_exhausted": retry_exhausted,
            "avg_rtt_ms": round(avg_rtt, 2),
            "min_rtt_ms": round(min_rtt, 2),
            "max_rtt_ms": round(max_rtt, 2),
            "categories": cat_counts,
            "directions": dir_counts,
        }
