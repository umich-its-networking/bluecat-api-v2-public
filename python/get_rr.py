#!/usr/bin/env python
"""Get Resource Record by absoluteName"""
import csv
import sys
import logging
import argparse
import json
import requests
from bamv2 import BAMv2


def parse(description="Get Resource Records by hostname"):
    """define arguments"""
    config = BAMv2.argparsecommon(description)
    config.add_argument(
        "hostname",
    )
    return config


def main():
    """get resource record by absoluteName"""
    description = "get_rr.py hostname"
    config = parse(description)
    args = config.parse_args()
    hostname = args.hostname
    hostname = hostname.rstrip(".")  # remove trailing dot, if any

    logger = logging.getLogger()
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s")
    logger.setLevel(args.logging)

    session = BAMv2(args.server, args.username, args.password, args.timeout)

    # print(f"looking for {hostname}")
    data = session.get_rr(hostname)
    # print(f"{data}")
    if data:
        print(json.dumps(data))
    else:
        print(f"Not found: {hostname}")


if __name__ == "__main__":
    main()
