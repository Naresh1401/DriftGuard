"""Tests for the AI breach SDK client and CLI.

The client uses urllib so we patch `urllib.request.urlopen` rather than
spinning up a real HTTP server. The CLI is exercised via `main(argv=...)`.
"""
from __future__ import annotations

import io
import json
from contextlib import contextmanager
from unittest.mock import patch

from sdk.ai_breach_client import AIBreachClient, build_signal
from sdk.ai_breach_cli import main as cli_main


class _FakeResp:
    def __init__(self, payload):
        self._buf = io.BytesIO(json.dumps(payload).encode("utf-8"))

    def read(self):
        return self._buf.getvalue()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@contextmanager
def _mock_http(payloads):
    """Yield a list that captures the request URLs/methods/bodies."""
    captured = []
    queue = list(payloads)

    def _fake(req, timeout=None):
        body = req.data.decode("utf-8") if req.data else None
        captured.append({"method": req.get_method(), "url": req.full_url, "body": body})
        return _FakeResp(queue.pop(0))

    with patch("sdk.ai_breach_client.urllib.request.urlopen", _fake):
        yield captured


# ---------------------------------------------------------------------------
# build_signal
# ---------------------------------------------------------------------------

def test_build_signal_defaults():
    s = build_signal(actor_type="agent", actor_id="a-1", action="prompt")
    assert s["actor_type"] == "agent"
    assert s["actor_id"] == "a-1"
    assert s["action"] == "prompt"
    assert s["prompt_size_tokens"] == 0
    assert s["contains_instruction_tokens"] is False
    assert isinstance(s["timestamp"], str) and "T" in s["timestamp"]
    assert s["metadata"] == {}


def test_build_signal_overrides():
    s = build_signal(
        actor_type="nhi",
        actor_id="svc-7",
        action="tool_call",
        tool_name="github.create_pr",
        prompt_size_tokens=1200,
        contains_instruction_tokens=True,
        metadata={"trace": "abc"},
    )
    assert s["tool_name"] == "github.create_pr"
    assert s["prompt_size_tokens"] == 1200
    assert s["contains_instruction_tokens"] is True
    assert s["metadata"] == {"trace": "abc"}


# ---------------------------------------------------------------------------
# AIBreachClient
# ---------------------------------------------------------------------------

def test_patterns_get():
    client = AIBreachClient("http://x")
    with _mock_http([{"count": 7, "patterns": []}]) as cap:
        out = client.patterns()
    assert out["count"] == 7
    assert cap[0]["method"] == "GET"
    assert cap[0]["url"].endswith("/api/v1/ai-breach/patterns")
    assert cap[0]["body"] is None


def test_scan_post_serialises_signals():
    client = AIBreachClient("http://x/")
    sig = build_signal(actor_type="agent", actor_id="a", action="prompt")
    with _mock_http([{"detections": [], "aggregate": {"alert_level": "Watch"}}]) as cap:
        out = client.scan([sig])
    assert out["aggregate"]["alert_level"] == "Watch"
    assert cap[0]["method"] == "POST"
    body = json.loads(cap[0]["body"])
    assert body == {"signals": [sig]}


def test_playbook_path():
    client = AIBreachClient("http://x")
    with _mock_http([{"pattern": "Prompt_Injection"}]) as cap:
        client.playbook("Prompt_Injection")
    assert cap[0]["url"].endswith("/playbooks/Prompt_Injection")


def test_correlate_payload_shape():
    client = AIBreachClient("http://x")
    with _mock_http([{"findings": []}]) as cap:
        client.correlate([{"a": 1}], [{"actor_id": "u-1", "pattern": "Boundary_Drift", "timestamp": "now"}], window_minutes=120)
    body = json.loads(cap[0]["body"])
    assert body["window_minutes"] == 120
    assert body["signals"] == [{"a": 1}]
    assert body["human_events"][0]["actor_id"] == "u-1"


def test_api_key_header_is_set():
    client = AIBreachClient("http://x", api_key="secret")
    captured = {}

    def _fake(req, timeout=None):
        captured["auth"] = req.headers.get("Authorization")
        return _FakeResp({"ok": True})

    with patch("sdk.ai_breach_client.urllib.request.urlopen", _fake):
        client.patterns()
    assert captured["auth"] == "Bearer secret"


def test_http_error_is_wrapped():
    import urllib.error

    client = AIBreachClient("http://x")

    def _raise(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 503, "boom", {}, io.BytesIO(b'{"detail":"down"}'))

    with patch("sdk.ai_breach_client.urllib.request.urlopen", _raise):
        try:
            client.patterns()
        except RuntimeError as e:
            assert "503" in str(e)
        else:
            raise AssertionError("expected RuntimeError")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_cli_demo_invokes_client(capsys):
    with _mock_http([{"alert_level": "Critical", "overall_risk_score": 85}]):
        rc = cli_main(["demo", "--base", "http://x"])
    assert rc == 0
    out = capsys.readouterr().out
    assert '"alert_level": "Critical"' in out


def test_cli_playbook_requires_pattern(capsys):
    try:
        cli_main(["playbook", "--base", "http://x"])
    except SystemExit as e:
        assert e.code == 2
    else:
        raise AssertionError("argparse should have exited")
