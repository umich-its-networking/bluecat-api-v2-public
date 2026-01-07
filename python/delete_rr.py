#!/usr/bin/env python
"""Delete Resource Record by absoluteName"""
import csv
import sys
import logging
import argparse
import json
import requests
from bamv2 import BAMv2


def parse(description="Delete Resource Records by hostname"):
    """define arguments"""
    config = BAMv2.argparsecommon(description)
    config.add_argument(
        "hostname",
    )
    return config


def  get_rr(session, hostname):
    '''get resource record by absoluteName'''
    url = f"{session.mainurl}/resourceRecords?fields=embed(dependentRecords)&filter=absoluteName:eq(\"{hostname}\")"
    response = requests.get(
                url, headers=session.auth_header, timeout=session.timeout
            )
    data = response.json()
    if data['count'] == 0:
        print(f"Not found: hostname")
        return None
    return data
    #print(json.dumps(data))


def delete_rr(session,id):
    '''Delete object by id'''
    logger = logging.getLogger()
    url=f"{session.mainurl}/resourceRecords/{id}"
    response=requests.delete(
                url, headers=session.auth_header, timeout=session.timeout
            )
    if response.status_code in (202,204):
        logger.debug("Deleted")
    else:
        print(response)
        print(f"ERROR: {response.json()}")


def main():
    """Execute program"""
    description = "delete_rr.py hostname"
    config = parse(description)
    args = config.parse_args()
    hostname=args.hostname
    hostname=hostname.rstrip(".")   # remove trailing dot, if any

    logger = logging.getLogger()
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s")
    logger.setLevel(args.logging)

    session = BAMv2(args.server, args.username, args.password, args.timeout)

    #print(f"looking for {hostname}")
    data=session.get_rr(hostname)
    #print(f"got {data}")
    if data:
        for obj in data:
            print(f"Deleting: {obj}")
            id=obj['id']
            delete_rr(session,id)

if __name__ == "__main__":
    main()
