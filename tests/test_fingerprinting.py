from proxy.fingerprinter import Fingerprinter, RequestContext


def test_fingerprints_openai_chat():
    fp = Fingerprinter()
    ctx = RequestContext(
        host="api.openai.com",
        path="/v1/chat/completions",
        method="POST",
        headers={"OpenAI-Organization": "demo"},
        body="{}",
    )
    result = fp.fingerprint(ctx)
    assert result is not None
    assert result.service_name == "OpenAI"
    assert result.model_type == "chat"
    assert result.confidence >= 0.5
