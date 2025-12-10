# API & Interfaces (Synthetic Demo)

This project primarily operates as a transparent proxy. The following interfaces describe the core classes and expected behaviors for extension or integration.

## Python Interfaces

### Fingerprinter (`proxy/fingerprinter.py`)
- `fingerprint(ctx: RequestContext) -> Optional[FingerprintResult]`
  - Inputs: host, path, method, headers, optional TLS JA3/SNI.
  - Outputs: service name, model type, API version, risk level, confidence, matched signals.

### DLP Engine (`proxy/dlp_engine.py`)
- `analyze(prompt: str) -> DLPResult`
  - Regex + entropy + optional spaCy to detect PII/secrets.
  - Scores: `pii_score` (0–1), `secret_leakage_score` (0–1), `sensitive_segments`.

### Policy Engine (`proxy/policy_engine.py`)
- `evaluate(fp: Optional[FingerprintResult], dlp: DLPResult) -> PolicyDecision`
  - Rules: no PII, redact secrets, block high secret risk, block non-whitelisted external LLMs, safe-mode rewrite for jailbreaky prompts.

### Redactor (`proxy/redactor.py`)
- `redact(prompt: str, dlp: DLPResult, mode: str = "redact") -> RedactionOutcome`
  - Modes: `redact`, `block`, `mask`, `rewrite`.
  - Tokens: `[REDACTED—PII]`, `[REDACTED—SECRET]`, masked hashes.

### Governance Logger (`proxy/governance_logger.py`)
- `log(event: GovernanceEvent) -> None`
- `latest(limit: int = 50) -> List[GovernanceEvent]`
- `stats() -> Dict[str, int]`
  - Persists JSONL and CSV entries with session/service/model/policy/risk metadata.

### MITM Layer (`proxy/mitm_layer.py`)
- `generate_root_ca() -> CertificateBundle`
- `start(listen_addr: str) -> None`
  - Wraps proxy.py to provide synthetic MITM interception; lab-only.

## HTTP Behavior (Synthetic)
When wired into proxy.py, requests are intercepted, classified, scanned, governed, and optionally blocked or rewritten. The provided `--demo` mode runs this flow without any network calls.

## Dashboard Events
The React dashboard currently consumes a synthetic event feed. To connect to live events, expose a WebSocket endpoint that streams `GovernanceEvent` objects serialized to JSON.


