"""Offline tests for the license + health surface (``license_info``,
``health_summary``), replayed from an anonymized capture of a live 7.6
supervisor. No appliance, no network.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from pyfortisiem import FortiSIEMClient
from pyfortisiem.models import HealthOrg, LicenseInfo

FIXTURE = Path(__file__).parent / "fixtures" / "system_responses.json"
BEFORE_END = datetime(2026, 10, 1, tzinfo=timezone.utc)
AFTER_END = datetime(2027, 3, 1, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def cap() -> dict:
    return json.loads(FIXTURE.read_text())


def test_license_info_types_the_gui_fields(cap):
    lic = LicenseInfo.model_validate(cap["sec_license"])
    assert lic.serial == "FSMS01TM00000000"
    assert lic.type == "Enterprise"
    assert lic.eps_licensed == 15000
    assert lic.license_end == datetime(2027, 1, 23, 8, tzinfo=timezone.utc)  # GUI: "Jan 23,2027"
    names = [f.resource_name for f in lic.features]
    assert "Maintenance and Support" in names
    assert lic.warnings == []


def test_license_validity_follows_end_time(cap):
    lic = LicenseInfo.model_validate(cap["sec_license"])
    assert lic.is_valid(BEFORE_END)
    assert lic.days_left(BEFORE_END) == 114
    assert not lic.is_valid(AFTER_END)
    assert lic.days_left(AFTER_END) < 0


def test_license_without_serial_is_invalid(cap):
    d = dict(cap["sec_license"], sn="")
    assert not LicenseInfo.model_validate(d).is_valid(BEFORE_END)


def test_license_with_no_end_time_is_valid_while_serial_present(cap):
    d = dict(cap["sec_license"], licenseEndTime=0)
    lic = LicenseInfo.model_validate(d)
    assert lic.license_end is None and lic.days_left() is None
    assert lic.is_valid(AFTER_END)


def test_health_org_ok_needs_every_node_normal(cap):
    org = HealthOrg.model_validate(cap["health_summary"][0])
    assert org.ok
    assert [n.node_type for n in org.nodes] == ["Super", "Collector"]
    bad = json.loads(json.dumps(cap["health_summary"][0]))
    bad["nodes"][1]["status"] = "Critical"
    assert not HealthOrg.model_validate(bad).ok


def _client(cap, seen: list) -> FortiSIEMClient:
    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.url.path == "/phoenix/rest/h5/sec/license":
            return httpx.Response(200, json=cap["sec_license"])
        if req.url.path == "/phoenix/rest/system/health/summary":
            return httpx.Response(200, json=cap["health_summary"])
        return httpx.Response(404)

    c = FortiSIEMClient("fsm.example.com:443", "admin", "pw")
    c._client = httpx.Client(transport=httpx.MockTransport(handler))
    c._session = httpx.Client(transport=httpx.MockTransport(handler), cookies={"s": "abc"})
    return c


def test_license_info_uses_h5_session_with_csrf_header(cap):
    seen: list[httpx.Request] = []
    lic = _client(cap, seen).license_info()
    assert lic.serial == "FSMS01TM00000000"
    assert seen[0].headers["s"] == b"abc".hex().upper()


def test_health_summary_uses_basic_auth(cap):
    seen: list[httpx.Request] = []
    orgs = _client(cap, seen).health_summary()
    assert [o.name for o in orgs] == ["Super"] and orgs[0].ok
    assert seen[0].headers["authorization"].startswith("Basic ")
