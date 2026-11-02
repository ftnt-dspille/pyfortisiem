"""Offline tests for the FortiAI (GenAI) surface: key details, saved analyses
and the agentic triage stream, replayed from a live 7.6 capture (anonymized)."""

from __future__ import annotations

import json

import httpx
import pytest

from pyfortisiem import FortiSIEMClient
from pyfortisiem.models import AIAnalysis, AIKeyDetails


def _client(handler) -> FortiSIEMClient:
    c = FortiSIEMClient("fsm.example.com:443", "admin", "pw")
    c._session = httpx.Client(transport=httpx.MockTransport(handler), cookies={"s": "abc"})
    return c


def test_key_details_unwraps_the_double_encoded_body():
    key = {"key_type": "openai", "azure_ai_resource_name": "", "api_key": "********"}
    body = json.dumps(json.dumps(key))
    ctype = {"content-type": "application/json"}
    c = _client(lambda req: httpx.Response(200, content=body, headers=ctype))
    k = c.ai_key_details()
    assert isinstance(k, AIKeyDetails) and k.key_type == "openai" and k.configured


def test_key_details_unconfigured():
    assert not AIKeyDetails.model_validate({"key_type": "", "api_key": ""}).configured


def test_incident_ai_result_none_on_204():
    seen = {}

    def h(req):
        seen["url"] = str(req.url)
        return httpx.Response(204)

    assert _client(h).incident_ai_result(216) is None
    assert "incident/airesult/216" in seen["url"] and "analysisType=AGENTIC" in seen["url"]


def test_incident_ai_result_saved():
    saved = {"result": "#### Summary", "ownerId": 7, "lastModified": 1793626257000}
    c = _client(lambda req: httpx.Response(200, json=saved))
    a = c.incident_ai_result(216, "BASIC")
    assert isinstance(a, AIAnalysis) and a.result == "#### Summary" and a.analysis_type == "BASIC"
    assert a.last_modified is not None


class _FakeWS:
    def __init__(self, frames):
        self.frames = [json.dumps(f) for f in frames]
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def send(self, data):
        self.sent.append(json.loads(data))

    def recv(self, timeout=None):
        return self.frames.pop(0)


FRAMES = [
    {"message": "Activating the incident triage agent...\n", "ws_id": "w1"},
    {
        "ws_id": "w1",
        "message": "Triage Steps for incident 216.\n",
        "incident_id": 216,
        "steps": [{"title": "1. Identify IOCs", "status": "Completed", "msg": None}],
    },
    {"ws_id": "w1", "message": "\n#### Incident Triage Summary\n\nTrue positive."},
    {
        "ws_id": "w1",
        "message": "\nYou can download the summary report at: "
        "[r.pdf](https://fsm.example.com/phoenix/genCustomizeReport?fileName=triage_report_1.pdf)\n",
    },
    {"message": "Success.", "ws_id": "w1", "finished": True},
]


def test_triage_incident_collects_the_stream(monkeypatch):
    pytest.importorskip("websockets")
    import websockets.sync.client as wsc

    fake = _FakeWS(list(FRAMES))
    monkeypatch.setattr(wsc, "connect", lambda *a, **k: fake)
    c = FortiSIEMClient("fsm.example.com:443", "admin", "pw")
    monkeypatch.setattr(c, "genai_websocket_url", lambda **k: "wss://x/ws/1")
    monkeypatch.setattr(c, "incident_planner_prompt", lambda i: "Follow these steps")
    seen = []
    run = c.triage_incident(216, on_message=seen.append)
    assert fake.sent == [
        {
            "question": "Triage incidents with ids: [216]",
            "optimize_triage": True,
            "triage_prompt": "Follow these steps",
        }
    ]
    assert run.finished and run.ws_id == "w1" and len(seen) == len(FRAMES)
    assert run.steps[0].status == "Completed"
    assert run.summary.startswith("#### Incident Triage Summary")
    assert run.report == "triage_report_1.pdf"


def test_planner_prompt_reads_the_story_at_first_seen():
    calls = []

    def h(req):
        calls.append(req)
        if req.url.path.endswith("incident/list"):
            return httpx.Response(
                200,
                json={
                    "fields": ["incidentFirstSeen", "origFirstSeenTime", "incidentId"],
                    "lightValueObjects": [
                        {"custId": 1, "data": [1793572800000, 1793572800000, 216]}
                    ],
                },
            )
        assert req.url.params["firstSeenTime"] == "1793572800000"
        return httpx.Response(
            200,
            json={
                "data": [
                    {"incidentId": 232, "plannerPrompt": "other"},
                    {"incidentId": 216, "plannerPrompt": "Follow these steps"},
                ]
            },
        )

    assert _client(h).incident_planner_prompt(216) == "Follow these steps"
    assert len(calls) == 2
