import logging
import re
from dataclasses import dataclass


@dataclass
class FingerprintResult:
    """Outcome of AI service fingerprinting."""

    service_name: str
    model_type: str
    api_version: str
    risk_level: str
    confidence: float
    matched_on: list[str]


@dataclass
class RequestContext:
    """Normalized HTTP request metadata used for fingerprinting."""

    host: str
    path: str
    method: str
    headers: dict[str, str]
    body: str | None = None
    tls_ja3: str | None = None
    sni: str | None = None


class Fingerprinter:
    """
    Lightweight AI service fingerprinter using hostname, headers, paths, and
    optional synthetic TLS hints. The rules are heuristic and educational only.
    """

    def __init__(self) -> None:
        """Prepare fingerprint rules and logger."""
        self.rules = self._build_rules()
        self.logger = logging.getLogger(__name__)

    def _build_rules(self) -> list[dict]:
        """Construct heuristic fingerprint rules for known AI providers."""
        # A condensed synthetic catalog; extend easily by adding tuples.
        catalog = [
            (
                "OpenAI",
                ["api.openai.com"],
                [r"/v1/chat/completions", r"/v1/completions", r"/v1/models"],
                ["OpenAI-Organization"],
                "chat",
                "v1",
            ),
            (
                "Anthropic",
                ["api.anthropic.com", "claude.ai"],
                [r"/v1/messages", r"/v1/complete"],
                ["Anthropic-Version"],
                "chat",
                "v1",
            ),
            (
                "Google Gemini",
                ["generativelanguage.googleapis.com", "gemini.google.com"],
                [r"/v1beta/models", r"/v1/models"],
                ["x-goog-api-client"],
                "multimodal",
                "v1beta",
            ),
            (
                "Azure OpenAI",
                ["*.openai.azure.com"],
                [r"/openai/deployments/.*/chat/completions"],
                ["api-key", "x-ms-client-request-id"],
                "chat",
                "2023-12-01-preview",
            ),
            (
                "HuggingFace",
                ["api-inference.huggingface.co", "huggingface.co"],
                [r"/models/", r"/pipeline/"],
                ["X-Requested-With"],
                "inference",
                "v1",
            ),
            (
                "Replicate",
                ["api.replicate.com"],
                [r"/v1/predictions"],
                ["Authorization"],
                "inference",
                "v1",
            ),
            (
                "Cohere",
                ["api.cohere.ai"],
                [r"/v1/generate", r"/v1/chat"],
                ["Cohere-Version"],
                "chat",
                "v1",
            ),
            (
                "Mistral",
                ["api.mistral.ai"],
                [r"/v1/chat/completions", r"/v1/models"],
                ["Mistral-Version"],
                "chat",
                "v1",
            ),
            (
                "Perplexity",
                ["api.perplexity.ai"],
                [r"/chat/completions"],
                ["User-Agent"],
                "chat",
                "v1",
            ),
            (
                "AWS Bedrock",
                ["bedrock-runtime.*.amazonaws.com"],
                [r"/model/.*invoke"],
                ["X-Amz-Target"],
                "multimodal",
                "2023-06-01",
            ),
            (
                "IBM watsonx",
                ["us-south.ml.cloud.ibm.com"],
                [r"/ml/v1/generation"],
                ["Authorization"],
                "chat",
                "v1",
            ),
        ]
        rules = []
        for name, domains, paths, headers, model_type, api_version in catalog:
            domain_regexes = [self._wildcard_to_regex(d) for d in domains]
            path_regexes = [re.compile(p) for p in paths]
            rules.append(
                {
                    "service_name": name,
                    "domains": domain_regexes,
                    "paths": path_regexes,
                    "headers": [h.lower() for h in headers],
                    "model_type": model_type,
                    "api_version": api_version,
                    "risk_level": "medium" if name not in {"AWS Bedrock", "IBM watsonx"} else "low",
                }
            )
        return rules

    def _wildcard_to_regex(self, pattern: str) -> re.Pattern:
        """Convert wildcard domain patterns (e.g., *.example.com) to regex."""
        escaped = re.escape(pattern).replace(r"\*", ".*")
        return re.compile(f"^{escaped}$", re.IGNORECASE)

    def fingerprint(self, ctx: RequestContext) -> FingerprintResult | None:
        """
        Best-effort classification of target AI provider from request metadata.
        Returns None if confidence is too low.
        """
        host = ctx.host.lower()
        matched: list[tuple[dict, float, list[str]]] = []
        for rule in self.rules:
            signals = []
            score = 0.0
            if any(r.match(host) for r in rule["domains"]):
                score += 0.5
                signals.append("domain")
            if any(p.search(ctx.path) for p in rule["paths"]):
                score += 0.3
                signals.append("path")
            header_keys = [h.lower() for h in ctx.headers.keys()]
            if any(h in header_keys for h in rule["headers"]):
                score += 0.15
                signals.append("header")
            if ctx.tls_ja3 and rule["service_name"] in ("OpenAI", "Anthropic"):
                score += 0.05
                signals.append("tls-ja3")
            if score >= 0.45:
                matched.append((rule, score, signals))
        if not matched:
            return None
        rule, score, signals = sorted(matched, key=lambda x: x[1], reverse=True)[0]
        self.logger.debug(
            "Fingerprint matched %s with score %.2f via %s", rule["service_name"], score, signals
        )
        return FingerprintResult(
            service_name=rule["service_name"],
            model_type=rule["model_type"],
            api_version=rule["api_version"],
            risk_level=rule["risk_level"],
            confidence=round(score, 2),
            matched_on=signals,
        )
