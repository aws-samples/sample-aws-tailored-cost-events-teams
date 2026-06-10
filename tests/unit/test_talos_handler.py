"""
Talos remediation tests for handler.py.

Covers two Medium findings:

* **5276ea22 — No size limit on SNS message JSON parsing.** ``handler._extract``
  calls ``json.loads`` on the SNS ``Message`` with no upper bound. SNS permits
  messages up to 256 KB; an oversized/crafted body should be rejected BEFORE any
  parse attempt so the function never allocates an unbounded parse tree.

* **5d523fa8 — Exception messages exposed in Lambda response.** ``handler.handler``
  must keep the CODE-1 contract (a per-record failure PROPAGATES so SNS retries /
  the SQS DLQ engages) but must NOT surface the raw exception text — which can
  contain internal detail, file paths, or secrets — to the caller/response. The
  full detail is logged to CloudWatch (``log.exception``); the raised error is a
  generic, sanitized message.
"""

from __future__ import annotations

import json

import pytest

import handler


SENTINEL = "SENTINEL_SECRET_/var/task/internal/path_abc123_DO_NOT_LEAK"


# ===========================================================================
# 5276ea22 — SNS Message size cap BEFORE json.loads
# ===========================================================================
class TestSnsMessageSizeCap:
    def test_cap_constant_exists_and_is_sane(self):
        cap = getattr(handler, "_MAX_SNS_MESSAGE_BYTES", None)
        assert isinstance(cap, int), (
            "5276ea22: handler must define an int _MAX_SNS_MESSAGE_BYTES cap"
        )
        # SNS max message size is 256 KB; the cap should be at/below that bound.
        assert 0 < cap <= 256 * 1024

    def test_oversized_message_rejected_before_parse(self, monkeypatch):
        """
        An SNS Message larger than the cap must be rejected WITHOUT calling
        json.loads (no unbounded parse). We spy on handler.json.loads and assert
        it is never invoked for the oversized body.
        """
        cap = handler._MAX_SNS_MESSAGE_BYTES
        # Valid JSON shape, but pathologically large (> cap).
        oversized = "[" + ("0," * (cap)) + "0]"
        assert len(oversized) > cap

        calls = {"n": 0}
        real_loads = json.loads

        def spy_loads(*a, **k):
            calls["n"] += 1
            return real_loads(*a, **k)

        monkeypatch.setattr(handler.json, "loads", spy_loads)

        rec = {"Sns": {"Message": oversized}}
        result = handler._extract(rec)

        assert result is None, "5276ea22: oversized SNS message must be skipped"
        assert calls["n"] == 0, (
            "5276ea22: json.loads must NOT be called on an oversized SNS message "
            "(parse must be skipped before allocation)"
        )

    def test_normal_message_still_parses(self, monkeypatch):
        """A normal-sized JSON SNS message parses as before (no regression)."""
        event = {"source": "aws.ce", "detail": {"accountId": "123456789012"}}
        rec = {"Sns": {"Message": json.dumps(event)}}
        extracted = handler._extract(rec)
        assert extracted is not None
        assert extracted["source"] == "aws.ce"


# ===========================================================================
# 5d523fa8 — raw exception text must NOT reach the response, but failure
# must still PROPAGATE (CODE-1 preserved).
# ===========================================================================
class TestExceptionNotLeaked:
    def test_raised_error_has_no_raw_exception_text(
        self, aws_mocks, fake_teams, cad_sns_records, monkeypatch
    ):
        import routing

        monkeypatch.setattr(routing, "_account_tag", lambda _acct: None)

        def boom(*_a, **_k):
            # A failure whose message carries internal detail / a "secret".
            raise RuntimeError(SENTINEL)

        monkeypatch.setattr(handler, "write_to_s3", boom)

        with pytest.raises(Exception) as exc_info:
            handler.handler(cad_sns_records, None)

        # CODE-1 preserved: it still raised (SNS retry / DLQ engages).
        # 5d523fa8: the raised error must NOT contain the raw exception text.
        rendered = f"{exc_info.value}"
        assert SENTINEL not in rendered, (
            "5d523fa8: raw exception text leaked into the raised/response error"
        )

    def test_raised_error_chain_is_suppressed(
        self, aws_mocks, fake_teams, cad_sns_records, monkeypatch
    ):
        """
        The original exception must not be chained into the public error (so the
        Lambda runtime's stackTrace/errorMessage cannot echo internal detail).
        """
        import routing

        monkeypatch.setattr(routing, "_account_tag", lambda _acct: None)

        def boom(*_a, **_k):
            raise RuntimeError(SENTINEL)

        monkeypatch.setattr(handler, "write_to_s3", boom)

        with pytest.raises(Exception) as exc_info:
            handler.handler(cad_sns_records, None)

        err = exc_info.value
        # __cause__ must not be set to the sentinel-bearing exception, and the
        # implicit context must be suppressed (raise ... from None).
        assert getattr(err, "__cause__", None) is None
        assert getattr(err, "__suppress_context__", False) is True
        assert SENTINEL not in f"{getattr(err, '__cause__', '')}"

    def test_coh_pull_error_is_sanitized(self, aws_mocks, fake_teams, monkeypatch):
        """run_coh_pull must apply the same sanitization (CODE-1 path)."""
        monkeypatch.setattr(
            handler, "pull_coh_recommendations", lambda *a, **k: [{"x": 1}]
        )

        def boom(*_a, **_k):
            raise RuntimeError(SENTINEL)

        monkeypatch.setattr(handler, "process_coh_recommendation", boom)

        with pytest.raises(Exception) as exc_info:
            handler.run_coh_pull()

        assert SENTINEL not in f"{exc_info.value}", (
            "5d523fa8: COH pull leaked raw exception text"
        )
