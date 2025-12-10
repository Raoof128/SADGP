import logging
from dataclasses import dataclass

from proxy.dlp_engine import DLPResult
from proxy.fingerprinter import FingerprintResult


@dataclass
class PolicyDecision:
    """Result of policy evaluation including action and triggered rules."""

    action: str  # allow | redact | block | mask | rewrite
    reasons: list[str]
    policy_matches: list[str]
    parameters: dict[str, str]


class PolicyEngine:
    """
    Declarative policy checks; extendable with simple rule functions.
    """

    def __init__(
        self, whitelist: list[str] | None = None, enforce_external_block: bool = False
    ) -> None:
        """Configure policy engine with optional whitelist and external block flag."""
        self.whitelist = set(whitelist or [])
        self.enforce_external_block = enforce_external_block
        self.logger = logging.getLogger(__name__)
        self._severity = ["allow", "redact", "mask", "rewrite", "block"]

    def _bump_action(self, current: str, candidate: str) -> str:
        """Pick the higher-severity action."""
        return (
            candidate
            if self._severity.index(candidate) > self._severity.index(current)
            else current
        )

    def evaluate(self, fp: FingerprintResult | None, dlp: DLPResult) -> PolicyDecision:
        """
        Evaluate policies against fingerprint and DLP results to determine action.
        """
        matches: list[str] = []
        reasons: list[str] = []
        action = "allow"
        params: dict[str, str] = {}

        if dlp.pii_score >= 0.2:
            matches.append("RULE_NO_PII")
            reasons.append("PII detected")
            action = self._bump_action(action, "redact")
        if dlp.secret_leakage_score >= 0.2:
            matches.append("RULE_REDACT_SECRETS")
            reasons.append("Secrets detected")
            action = self._bump_action(action, "redact")
        if dlp.secret_leakage_score >= 0.4:
            matches.append("RULE_BLOCK_SECRETS")
            reasons.append("High secret risk")
            action = self._bump_action(action, "block")
        if fp and self.enforce_external_block and fp.service_name not in self.whitelist:
            matches.append("RULE_BLOCK_EXTERNAL")
            reasons.append(f"External LLM {fp.service_name} not whitelisted")
            action = self._bump_action(action, "block")
        # Simple jailbreak heuristic: presence of adversarial phrases.
        if dlp.raw_prompt and "ignore previous" in dlp.raw_prompt.lower():
            matches.append("RULE_SAFE_MODE_REWRITE")
            reasons.append("Jailbreak-like content")
            action = self._bump_action(action, "rewrite")
            params["rewrite"] = "safe-mode"

        if not matches:
            reasons.append("No policies triggered")

        self.logger.debug("Policy decision %s; reasons=%s; matches=%s", action, reasons, matches)
        return PolicyDecision(
            action=action, reasons=reasons, policy_matches=matches, parameters=params
        )
