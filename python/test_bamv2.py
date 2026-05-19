#!/usr/bin/env python
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import bamv2
from bamv2 import BAMv2


class DummyResponse:
    def __init__(self, status_code, json_data):
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data

    @property
    def text(self):
        return json.dumps(self._json_data) if self._json_data is not None else ""


def make_bam(monkeypatch):
    monkeypatch.setattr(bamv2.BAMv2, "login", lambda self: None)
    bam = BAMv2(server="server", username="user", password="pass")
    bam.auth_header_links = {
        "accept": "application/hal+json",
        "Authorization": "Basic abc",
        "Content-Type": "application/hal+json",
    }
    bam.auth_header_nolinks = {
        "accept": "application/json",
        "Authorization": "Basic abc",
        "Content-Type": "application/hal+json",
    }
    bam.auth_header_default = bam.auth_header_links
    bam.timeout = 30
    return bam


def test_argparsecommon_parses_expected_arguments():
    parser = BAMv2.argparsecommon("test description")
    args = parser.parse_args([
        "--server",
        "host",
        "--username",
        "user",
        "--password",
        "pass",
        "--configuration_name",
        "cfg",
        "--view_name",
        "view",
        "--timeout",
        "15",
        "--no-links",
    ])

    assert args.server == "host"
    assert args.username == "user"
    assert args.password == "pass"
    assert args.configuration_name == "cfg"
    assert args.view_name == "view"
    assert args.timeout == 15
    assert args.links is False


def test_removelinks_removes_nested_links():
    data = {
        "_links": {"self": {"href": "/api/v2/example"}},
        "name": "test",
        "nested": {"_links": {"self": {"href": "/api/v2/nested"}}, "value": 1},
    }

    result = BAMv2.removelinks(data)

    assert "_links" not in result
    assert "_links" not in result["nested"]
    assert result["name"] == "test"
    assert result["nested"]["value"] == 1


def test_match_type_classifies_common_identifiers(monkeypatch):
    bam = make_bam(monkeypatch)

    assert bam.match_type("1.2.3.4") == ("IP4Address", "1.2.3.4")
    assert bam.match_type("2001:db8::1") == ("IP6Address", "2001:db8::1")
    assert bam.match_type("10.0.0.0/24") == ("CIDR", "10.0.0.0/24")
    assert bam.match_type("10.0.0.1-10.0.0.255") == ("range", "10.0.0.1-10.0.0.255")
    assert bam.match_type("00:11:22:33:44:55") == ("MACAddress", "00:11:22:33:44:55")
    assert bam.match_type("example.com") == ("fqdn", "example.com")
    assert bam.match_type("12345") == ("id", 12345)
    assert bam.match_type("not-a-standard-identifier") == (
        "other",
        "not-a-standard-identifier",
    )


def test_format_mac_address_normalizes_dotted_mac():
    assert BAMv2.format_mac_address("0011.2233.4455") == "00-11-22-33-44-55"
    assert BAMv2.format_mac_address("00-11-22-33-44-55") == "00-11-22-33-44-55"
    assert BAMv2.format_mac_address("001122334455") == "001122334455"


def test_get_fqdn_or_cidr_routes_to_zone_network_and_block(monkeypatch):
    bam = make_bam(monkeypatch)

    def fake_get(url, headers, timeout):
        if "/zones?" in url:
            return DummyResponse(200, {"data": [{"id": 101, "name": "example.com"}]})
        if "/networks?" in url:
            return DummyResponse(200, {"data": [{"id": 201, "range": "192.168.0.0/24"}]})
        if "/blocks?" in url:
            return DummyResponse(200, {"data": [{"id": 301, "range": "192.168.0.0/24"}]})
        return DummyResponse(404, {"data": []})

    monkeypatch.setattr(bamv2.requests, "get", fake_get)

    kind, data = bam.get_fqdn_or_cidr("example.com")
    assert kind == "zone"
    assert data == [{"id": 101, "name": "example.com"}]

    kind, data = bam.get_fqdn_or_cidr("192.168.0.0/24")
    assert kind == "network"
    assert data == [{"id": 201, "range": "192.168.0.0/24"}]

    kind, data = bam.get_fqdn_or_cidr("192.168.0.0/24", type="block")
    assert kind == "block"
    assert data == [{"id": 301, "range": "192.168.0.0/24"}]
