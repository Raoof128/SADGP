import logging
from dataclasses import dataclass

from proxy.dlp_engine import DLPResult


@dataclass
class RedactionOutcome:
    action: str  # allow | redact | block | mask | rewrite
    redacted_text: str | None
    blocked: bool
    notes: list[str]


REDACTION_TOKENS = {
    "pii": "[REDACTED—PII]",
    "secret": "[REDACTED—SECRET]",
    "high_entropy": "[REDACTED—SECRET]",
}


class Redactor:
    """Redacts, masks, rewrites, or blocks prompts based on DLP findings."""

    def __init__(self) -> None:
        """Initialize redactor with module logger."""
        self.logger = logging.getLogger(__name__)

    def redact(self, prompt: str, dlp: DLPResult, mode: str = "redact") -> RedactionOutcome:
        """Apply the selected redaction/masking/blocking strategy to a prompt."""
        if mode == "block":
            return RedactionOutcome(
                action="block", redacted_text=None, blocked=True, notes=["blocked by policy"]
            )
        if mode == "mask":
            return self._mask(prompt, dlp)
        if mode == "rewrite":
            rewritten = "This prompt was rewritten to safe mode. Original content withheld."
            return RedactionOutcome(
                action="rewrite",
                redacted_text=rewritten,
                blocked=False,
                notes=["safe-mode rewrite"],
            )
        return self._basic_redact(prompt, dlp)

    def _basic_redact(self, prompt: str, dlp: DLPResult) -> RedactionOutcome:
        """Replace sensitive segments with redaction tokens; block on high risk."""
        redacted = prompt
        for segment in sorted(dlp.sensitive_segments, key=lambda s: s.start, reverse=True):
            token = REDACTION_TOKENS.get(segment.label, "[REDACTED]")
            redacted = redacted[: segment.start] + token + redacted[segment.end :]
        blocked = dlp.pii_score >= 0.8 or dlp.secret_leakage_score >= 0.8
        notes = []
        if blocked:
            notes.append("blocked due to high risk")
        elif redacted != prompt:
            notes.append("redaction applied")
        else:
            notes.append("no redaction needed")
        if blocked:
            self.logger.warning(
                "Prompt blocked due to high risk (pii=%.2f, secret=%.2f)",
                dlp.pii_score,
                dlp.secret_leakage_score,
            )
        elif redacted != prompt:
            self.logger.info("Prompt redaction applied (%d segments)", len(dlp.sensitive_segments))
        return RedactionOutcome(
            action="redact", redacted_text=redacted, blocked=blocked, notes=notes
        )

    def _mask(self, prompt: str, dlp: DLPResult) -> RedactionOutcome:
        """Mask sensitive segments with hashed tokens."""
        masked = prompt
        for segment in sorted(dlp.sensitive_segments, key=lambda s: s.start, reverse=True):
            masked_segment = self._hash_like(segment.value)
            masked = masked[: segment.start] + masked_segment + masked[segment.end :]
        return RedactionOutcome(
            action="mask", redacted_text=masked, blocked=False, notes=["masking applied"]
        )

    def _hash_like(self, value: str) -> str:
        """Create a deterministic mask token for a value."""
        return f"[MASK:{abs(hash(value)) % 10_000_000}]"
