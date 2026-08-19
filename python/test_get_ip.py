#!/usr/bin/env python
import os
import sys
import json

sys.path.insert(0, os.path.dirname(__file__))

import get_ip
import bamv2 as real_bamv2


def test_parse_ip_arg():
    parser = get_ip.parse()
    args = parser.parse_args(["1.2.3.4"])
    assert args.ip == "1.2.3.4"


def test_main_prints_ip_when_found(monkeypatch, capsys):
    class FakeSession:
        # provide argparsecommon but ensure args.configuration exists
        @staticmethod
        def argparsecommon(description=""):
            p = real_bamv2.BAMv2.argparsecommon(description)
            p.set_defaults(configuration=None)
            return p

        def __init__(self, server, username, password, timeout, configuration_name=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get_ip(self, ip):
            return ({"count": 1, "data": [{"id": 7, "address": ip}]}, None)

    monkeypatch.setattr(get_ip, "BAMv2", FakeSession)
    monkeypatch.setattr(sys, "argv", [
        "get_ip.py",
        "--server",
        "s",
        "--username",
        "u",
        "--password",
        "p",
        "1.2.3.4",
    ])

    get_ip.main()
    captured = capsys.readouterr()
    out = captured.out.strip()
    assert "'id': 7" in out or '"id": 7' in out


def test_main_prints_not_found(monkeypatch, capsys):
    class FakeSessionNotFound:
        @staticmethod
        def argparsecommon(description=""):
            p = real_bamv2.BAMv2.argparsecommon(description)
            p.set_defaults(configuration=None)
            return p

        def __init__(self, server, username, password, timeout, configuration_name=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get_ip(self, ip):
            return ({"count": 0, "data": []}, None)

    monkeypatch.setattr(get_ip, "BAMv2", FakeSessionNotFound)
    monkeypatch.setattr(sys, "argv", [
        "get_ip.py",
        "--server",
        "s",
        "--username",
        "u",
        "--password",
        "p",
        "2.2.2.2",
    ])

    get_ip.main()
    captured = capsys.readouterr()
    assert "Not found: 2.2.2.2" in captured.out


def test_main_prints_error_on_error(monkeypatch, capsys):
    class FakeSessionError:
        @staticmethod
        def argparsecommon(description=""):
            p = real_bamv2.BAMv2.argparsecommon(description)
            p.set_defaults(configuration=None)
            return p

        def __init__(self, server, username, password, timeout, configuration_name=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get_ip(self, ip):
            return (None, "connection failed")

    monkeypatch.setattr(get_ip, "BAMv2", FakeSessionError)
    monkeypatch.setattr(sys, "argv", [
        "get_ip.py",
        "--server",
        "s",
        "--username",
        "u",
        "--password",
        "p",
        "3.3.3.3",
    ])

    get_ip.main()
    captured = capsys.readouterr()
    assert "ERROR: connection failed" in captured.out
