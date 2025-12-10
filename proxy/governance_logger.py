import csv
import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class GovernanceEvent:
    """Governance record for an intercepted request."""

    session_id: str
    user_id: str
    timestamp: float
    target_service: str
    model: str
    prompt_hash: str
    redaction_applied: bool
    risk_score: float
    policy_triggered: list[str]
    action: str
    notes: list[str]


class GovernanceLogger:
    """Persists governance events to JSONL and CSV for auditability."""

    def __init__(
        self,
        jsonl_path: Path = Path("governance_logs.jsonl"),
        csv_path: Path = Path("governance_logs.csv"),
    ) -> None:
        """Initialize logger with output paths for JSONL and CSV."""
        self.jsonl_path = jsonl_path
        self.csv_path = csv_path
        self.events: list[GovernanceEvent] = []
        self._csv_initialized = False
        self.logger = logging.getLogger(__name__)

    def log(self, event: GovernanceEvent) -> None:
        """Persist a governance event to memory, JSONL, and CSV."""
        self.events.append(event)
        self._write_jsonl(event)
        self._write_csv(event)
        self.logger.info(
            "Logged governance event for %s (action=%s)", event.target_service, event.action
        )

    def _write_jsonl(self, event: GovernanceEvent) -> None:
        """Append a governance event to JSONL file."""
        with open(self.jsonl_path, "a") as f:
            f.write(json.dumps(asdict(event)) + "\n")

    def _write_csv(self, event: GovernanceEvent) -> None:
        """Append a governance event to CSV file, writing headers on first use."""
        fieldnames = list(asdict(event).keys())
        new_file = not self.csv_path.exists()
        with open(self.csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if new_file:
                writer.writeheader()
            writer.writerow(asdict(event))

    def latest(self, limit: int = 50) -> list[GovernanceEvent]:
        """Return the most recent governance events."""
        return self.events[-limit:]

    def stats(self) -> dict[str, int]:
        """Aggregate counts per target service."""
        counts: dict[str, int] = {}
        for e in self.events:
            counts[e.target_service] = counts.get(e.target_service, 0) + 1
        return counts

    @staticmethod
    def synthetic_event(**kwargs) -> GovernanceEvent:
        """Create a populated GovernanceEvent for synthetic/demo purposes."""
        defaults = dict(
            session_id="session-demo",
            user_id="user-synthetic",
            timestamp=time.time(),
            target_service="OpenAI",
            model="gpt-4o",
            prompt_hash="demo123",
            redaction_applied=True,
            risk_score=0.5,
            policy_triggered=["RULE_NO_PII"],
            action="redact",
            notes=["synthetic demo"],
        )
        defaults.update(kwargs)
        return GovernanceEvent(**defaults)
