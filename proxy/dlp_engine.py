import logging
import math
import re
import secrets
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

PII_REGEXES = {
    "email": re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE),
    "phone": re.compile(r"\b\+?\d{1,2}[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}\b"),
    "medicare": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "tfn": re.compile(r"\b\d{3}\s?\d{3}\s?\d{3}\b"),
}

SECRET_REGEXES = {
    "api_key": re.compile(r"(?i)(api|token|secret|key)[=:]\s*['\"]?[A-Za-z0-9-_]{12,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"),
}


@dataclass
class SensitiveSegment:
    """Span of detected sensitive content within a prompt."""

    label: str
    value: str
    start: int
    end: int


@dataclass
class DLPResult:
    """Aggregate result of DLP analysis with scores and sensitive spans."""

    pii_score: float
    secret_leakage_score: float
    sensitive_segments: list[SensitiveSegment] = field(default_factory=list)
    raw_prompt: str | None = None


class DLPEngine:
    """
    Educational DLP scanner: regex + entropy + optional spaCy entities.
    Scores are 0-1; higher means riskier. Only synthetic prompts should be used.
    """

    def __init__(self, enable_spacy: bool = False, spacy_model: str = "en_core_web_sm") -> None:
        """Initialize the DLP engine, optionally enabling spaCy NER."""
        self.enable_spacy = enable_spacy
        self.nlp = None
        if self.enable_spacy:
            try:
                import spacy  # type: ignore

                self.nlp = spacy.load(spacy_model)
            except Exception as exc:  # pragma: no cover - optional dependency
                logger.warning("spaCy model load failed: %s; disabling spaCy.", exc)
                self.enable_spacy = False

    def _entropy(self, text: str) -> float:
        """Compute Shannon entropy for a token; higher suggests randomness/secrets."""
        if not text:
            return 0.0
        probs = [text.count(c) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in probs)

    def _scan_regexes(self, text: str) -> list[SensitiveSegment]:
        """Find regex-based PII and secret candidates."""
        findings: list[SensitiveSegment] = []
        for label, regex in PII_REGEXES.items():
            for m in regex.finditer(text):
                findings.append(
                    SensitiveSegment(label=label, value=m.group(), start=m.start(), end=m.end())
                )
        for label, regex in SECRET_REGEXES.items():
            for m in regex.finditer(text):
                findings.append(
                    SensitiveSegment(label=label, value=m.group(), start=m.start(), end=m.end())
                )
        return findings

    def _scan_entropy(self, text: str, threshold: float = 3.5) -> list[SensitiveSegment]:
        """Detect high-entropy tokens as potential secrets."""
        findings: list[SensitiveSegment] = []
        tokens = re.findall(r"[A-Za-z0-9\-_]{8,}", text)
        for token in tokens:
            ent = self._entropy(token)
            if ent >= threshold and len(token) >= 16:
                findings.append(
                    SensitiveSegment(
                        label="high_entropy",
                        value=token,
                        start=text.find(token),
                        end=text.find(token) + len(token),
                    )
                )
        return findings

    def _scan_spacy(self, text: str) -> list[SensitiveSegment]:
        """Run spaCy NER for broad entity detection if enabled."""
        if not self.enable_spacy or self.nlp is None:
            return []
        doc = self.nlp(text)
        labels = {"PERSON", "GPE", "ORG", "NORP", "LOC"}
        return [
            SensitiveSegment(
                label=ent.label_, value=ent.text, start=ent.start_char, end=ent.end_char
            )
            for ent in doc.ents
            if ent.label_ in labels
        ]

    def analyze(self, prompt: str) -> DLPResult:
        """
        Analyze a prompt for PII and secret indicators.
        Returns a DLPResult with scores and segments; never raises on parse errors.
        """
        if not isinstance(prompt, str):
            logger.warning("DLP analyze received non-string prompt; coercing to str.")
            prompt = str(prompt)
        regex_hits = self._scan_regexes(prompt)
        entropy_hits = self._scan_entropy(prompt)
        spacy_hits = self._scan_spacy(prompt)

        all_hits = regex_hits + entropy_hits + spacy_hits
        pii_hits = [
            h
            for h in all_hits
            if h.label in PII_REGEXES or h.label in {"PERSON", "GPE", "ORG", "NORP", "LOC"}
        ]
        secret_hits = [
            h for h in all_hits if h.label in SECRET_REGEXES or h.label == "high_entropy"
        ]

        pii_score = min(1.0, len(pii_hits) * 0.2)
        secret_score = min(
            1.0,
            len(secret_hits) * 0.25
            + (0.3 if any(h.label == "high_entropy" for h in secret_hits) else 0),
        )

        return DLPResult(
            pii_score=round(pii_score, 2),
            secret_leakage_score=round(secret_score, 2),
            sensitive_segments=all_hits,
            raw_prompt=prompt,
        )

    @staticmethod
    def synthetic_prompt_with_findings() -> str:
        """Provide a synthetic prompt containing detectable PII/secret patterns."""
        return "Contact Alice Example at alice@example.com or +1 202-555-0199 with token API_KEY_12345_FAKE."

    @staticmethod
    def random_secret() -> str:
        """Generate a high-entropy synthetic secret."""
        return secrets.token_urlsafe(24)
