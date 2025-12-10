from proxy.dlp_engine import DLPEngine


def test_detects_pii_and_secrets():
    engine = DLPEngine(enable_spacy=False)
    prompt = engine.synthetic_prompt_with_findings()
    result = engine.analyze(prompt)
    assert result.pii_score > 0
    assert result.secret_leakage_score > 0
    labels = {s.label for s in result.sensitive_segments}
    assert "email" in labels
    assert any(label in labels for label in ("api_key", "high_entropy"))
