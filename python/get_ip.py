#!/usr/bin/env python
"""Get IP object by IP address"""
import csv
import sys
import logging
import argparse
import json
import requests
from bamv2 import BAMv2


def parse(description="Get IP object by IP address"):
    """define arguments"""
    config = BAMv2.argparsecommon(description)
    config.add_argument(
        "ip",
    )
    return config


def main():
    """get IP object by IP address"""
    description = "get_ip.py ip"
    config = parse(description)
    args = config.parse_args()
    ip = args.ip

    logger = logging.getLogger()
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s")
    logger.setLevel(args.logging)

    session = BAMv2(args.server, args.username, args.password, args.timeout, configuration_name=args.configuration)

    with session:

        # print(f"looking for {ip}")
        response, error= session.get_ip(ip)
        if error:
            print(f"ERROR: {error}")
            return
        logger.debug(f"got {response}")
        if response['count'] == 0:
            print(f"Not found: {ip}")
            return
        if response['count'] > 1:
            print(f"ERROR: Multiple objects found for {ip}")
            print(f"{response}")
            return
        if not response["data"]:
            print(f"Not found: {ip}")
        print( response["data"][0])


if __name__ == "__main__":
    main()
