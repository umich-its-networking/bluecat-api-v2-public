#!/usr/bin/env python
"""Delete IP Object by IP Address"""
import csv
import sys
import logging
import argparse
import json
import requests
from bamv2 import BAMv2


def parse(description="Delete IP Objects by IP Address"):
    """define arguments"""
    config = BAMv2.argparsecommon(description)
    config.add_argument(
        "ip",
    )
    return config


def delete_ip(session,id):
    '''Delete object by id'''
    logger = logging.getLogger()
    url=f"{session.mainurl}/addresses/{id}"
    response=requests.delete(
                url, headers=session.auth_header, timeout=session.timeout
            )
    if response.status_code in (202,204):
        logger.debug("Deleted")
        return True
    else:
        print(response)
        print(f"ERROR: {response.json()}")
        return f"ERROR: {response.json()}"


def main():
    """Execute program"""
    description = "delete_ip.py ip"
    config = parse(description)
    args = config.parse_args()
    ip=args.ip

    logger = logging.getLogger()
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s")
    logger.setLevel(args.logging)

    session = BAMv2(args.server, args.username, args.password, args.timeout, configuration_name=args.configuration)

    with session:
        #print(f"looking for {ip}")
        response=session.get_ip(ip)
        logger.debug(f"got {response}")
        #print(f"got {response}")
        if response['count'] == 0:
            print(f"Not found: {ip}")
            return
        if response['count'] > 1:
            print(f"ERROR: Multiple objects found for {ip}")
            print(f"{response}")
            return
        data=response['data'][0]
        if data:
            for obj in data:
                print(f"Deleting: {obj}")
                id=obj['id']
                delete_ip(session,id)
        else:
            print(f"Not found: {ip}")

if __name__ == "__main__":
    main()
