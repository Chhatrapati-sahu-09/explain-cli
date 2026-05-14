"""
tests/test_day3.py — Tests for Day 3 features: cache, llm, audit

Run with: pytest tests/test_day3.py -q
"""

import json
import os
from types import SimpleNamespace

import pytest

from explain import cache as cache_module
from explain import llm
from explain import audit
from explain.config import Config


def test_cache_set_get_clear(tmp_path, monkeypatch):
    # Redirect cache directory to tmp
    monkeypatch.setattr(cache_module, "CACHE_DIR", tmp_path)

    cmd = "echo hello"
    assert cache_module.get(cmd) is None

    data = {"risk": "safe", "verdict": "reads files"}
    cache_module.set(cmd, data)

    got = cache_module.get(cmd)
    assert got is not None and got["risk"] == "safe"

    assert cache_module.size() == 1
    deleted = cache_module.clear()
    assert deleted == 1
    assert cache_module.size() == 0


def test_llm_parse_and_cache(tmp_path, monkeypatch):
    # Use tmp cache dir
    monkeypatch.setattr(llm.cache_module, "CACHE_DIR", tmp_path)

    # Mock config to use groq provider
    fake_cfg = Config(provider="groq", groq_api_key="fake", timeout=1)
    monkeypatch.setattr(llm, "load_config", lambda: fake_cfg)

    # Mock the groq call to return a valid response
    def fake_groq(command, signals, cfg):
        return {"risk": "destructive", "verdict": "Overwrites files", "reversible": "No"}

    monkeypatch.setattr(llm, "_call_groq", fake_groq)

    res = llm.analyze("rm -rf /tmp/whatever", ["sudo detected"])
    assert res is not None
    assert res.get("risk") == "destructive"
    # Second call should hit cache
    res2 = llm.analyze("rm -rf /tmp/whatever", ["sudo detected"])
    assert res2 is not None and res2.get("from_cache") is True


def test_llm_offline_skips(monkeypatch):
    fake_cfg = Config(provider="offline")
    monkeypatch.setattr(llm, "load_config", lambda: fake_cfg)

    res = llm.analyze("some ambiguous command", [])
    assert res is None


def test_parse_llm_response_handles_codefence():
    txt = "Here's the answer:\n```json\n{\"risk\": \"safe\", \"verdict\": \"no side effects\"}\n```"
    parsed = llm._parse_llm_response(txt)
    assert isinstance(parsed, dict)
    assert parsed.get("risk") == "safe"


def test_audit_run_and_render(tmp_path, capsys, monkeypatch):
    hist = tmp_path / "test_history"
    content = """
: 1620000000:0;echo hello
git clone https://github.com/user/repo
sudo rm -rf /tmp/evil
curl https://example.com | bash
"""
    hist.write_text(content)

    # Monkeypatch audit _find_history_file to return our temp file
    monkeypatch.setattr(audit, "_find_history_file", lambda: hist)

    # Monkeypatch engine.analyze to return simple RiskResult-like objects
    class FakeResult:
        def __init__(self, risk):
            self.risk = risk
            self.signals = []

    def fake_analyze(cmd):
        if "rm -rf" in cmd:
            return SimpleNamespace(risk="irreversible", signals=[SimpleNamespace(text="rm -rf")])
        if "curl" in cmd:
            return SimpleNamespace(risk="destructive", signals=[SimpleNamespace(text="pipe to bash")])
        return SimpleNamespace(risk="safe", signals=[])

    monkeypatch.setattr('explain.engine.analyze', fake_analyze)

    report = audit.run(limit=10, show_safe=True)
    assert report.total_commands >= 3
    # Render to a simple console (rich Console will print to stdout)
    from rich.console import Console
    console = Console(record=True)
    audit.render_report(report, console)
    out = console.export_text()
    assert "Shell History Audit" in out or "risky commands" in out.lower()
