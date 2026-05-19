#!/usr/bin/env python
import os
import sys
import json

# Ensure the `python/` directory is on sys.path so modules import correctly
sys.path.insert(0, os.path.dirname(__file__))

import get_rr
import bamv2 as real_bamv2


def test_parse_hostname_arg():
    parser = get_rr.parse()
    args = parser.parse_args(["example.com"])
    assert args.hostname == "example.com"


def test_main_prints_json_when_found(monkeypatch, capsys):
    class FakeSession:
        argparsecommon = real_bamv2.BAMv2.argparsecommon

        def __init__(self, server, username, password, timeout):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get_rr(self, hostname):
            return [{"id": 123, "absoluteName": hostname}]

    monkeypatch.setattr(get_rr, "BAMv2", FakeSession)
    monkeypatch.setattr(sys, "argv", [
        "get_rr.py",
        "--server",
        "s",
        "--username",
        "u",
        "--password",
        "p",
        "example.com",
    ])

    get_rr.main()
    captured = capsys.readouterr()
    out = captured.out.strip()
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["id"] == 123


def test_main_prints_not_found(monkeypatch, capsys):
    class FakeSessionNotFound:
        argparsecommon = real_bamv2.BAMv2.argparsecommon

        def __init__(self, server, username, password, timeout):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get_rr(self, hostname):
            return None

    monkeypatch.setattr(get_rr, "BAMv2", FakeSessionNotFound)
    monkeypatch.setattr(sys, "argv", [
        "get_rr.py",
        "--server",
        "s",
        "--username",
        "u",
        "--password",
        "p",
        "missing.example",
    ])

    get_rr.main()
    captured = capsys.readouterr()
    assert "Not found" in captured.out
