#!/usr/bin/env python
"""Get Network object by IP address"""
import csv
import sys
import logging
import argparse
import json
import requests
from bamv2 import BAMv2


def parse(description="Get Network object by IP address"):
    """define arguments"""
    config = BAMv2.argparsecommon(description)
    config.add_argument(
        "ip",
    )
    return config


def main():
    """get Network object by IP address"""
    description = "get_network.py ip"
    config = parse(description)
    args = config.parse_args()
    ip = args.ip

    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s")
    logging.getLogger().setLevel(args.logging)

    session = BAMv2(args.server, args.username, args.password, args.timeout, configuration_name=args.configuration_name)

    with session:

        # print(f"looking for network that includes {ip}")
        response, error= session.get_network(ip)
        if error:
            print(f"ERROR: {error}")
            return
        print( response)


if __name__ == "__main__":
    main()
