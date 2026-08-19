#!/usr/bin/env python
"""add_host_record.py -f <filename>
OR
add_host_record.py --hostname NAME --ip ADDRESS
(other options available)
"""

import csv
import sys
import logging
import argparse
import re
import requests
import ipaddress
from bamv2 import BAMv2


def add_host_record(dic, session):
    """Add Host Record"""

    #print(f"Adding Host Record for {dic['host']}", end=" ")

    #print('')

    logger = logging.getLogger()

    # should we allow multiple host records?
    # check if hostname exists - it should not
    host=dic["host"]
    url = f"{session.mainurl}/resourceRecord?filter=absoluteName:eq('{host}')"
    response = requests.get(
        url, headers=session.auth_header, timeout=session.timeout
    )
    if response.status_code == 200:
        print (f"host {host} exists, so we cannot create it")
        data = response.json()
        logging.debug(data)
        return
    logging.debug(f"host {host} does not exist, so we can create it")
    
    # find the zone and remaining hostname
    zoneobj,remainder,errormsg=session.find_zone(host)
    if errormsg:
        print("zone for {host} not found, {errormsg}")
        return
    zoneobj = session.removelinks(zoneobj)
    logging.debug(f"found zone {zoneobj}")
    logging.debug(f"remainder {remainder}")

    if dic['ext']:  # if user requested, create a Generic Record instead of a Host Record
        logging.debug(f"external IP {dic['ip']}, create Generic Record")
        add_generic_record(dic, session, zoneobj, remainder)
        return

    # check if the IP destination object exists
    ip=dic["ip"]
    response, error= session.get_ip(ip)
    if error:
        print(f"ERROR: {error}")
        return
    logging.debug(f"got {response}")
    if response['count'] == 0:
        logging.debug(f"Not found, need to create {ip}")
        # get network
        network_obj, error=session.get_network(ip)
        if error:
            print(f"ERROR: {error}")
            return
        if network_obj['count'] == 0:
            logging.debug(f"Network not found for: {ip}, use generic record")
            add_generic_record(dic, session, zoneobj, remainder)
            return
        
        
        return
    if response['count'] > 1:
        print(f"ERROR: Multiple objects found for {ip}")
        print(f"{response}")
        return

    ip_obj= response['data'][0]
    logging.debug(f"found ip {ip_obj}")
    create_host_record(session,zoneobj,remainder,ip_obj)


def create_host_record(session,zoneobj,remainder,ip_obj):
    '''once destination ip is found, create the record'''
    link = "/api/v2/zones/" + str(zoneobj['id']) + "/resourceRecords"
    logger = logging.getLogger()
    logging.debug(f"link {link}")

    url = f"https://{session.server}{link}"
    msg = {
        "type": "HostRecord",
        "name": remainder,
        "addresses": [ {
            "id": ip_obj['id'],
            "type": ip_obj['type']
        } ]
    }
    logging.debug(f"msg {msg}")
    response = requests.post(
        url, headers=session.auth_header, json=msg, timeout=session.timeout
    )
    if response.status_code != 201:
        print(f"Failed: {response.status_code} Error")
        print(response.text)
        logging.debug(response.text)
        return
    data = response.json()
    data=session.removelinks(data)
    print(f"Success, created {data}")
    
    logging.debug(data)
    return


def add_generic_record(dic, session, zoneobj, remainder):
    '''Add Generic Record'''
    msg={
        "type": "GenericRecord",
        "name": remainder,
        "recordType": "A",
        "rdata": dic["ip"]
    }
    link = "/api/v2/zones/" + str(zoneobj['id']) + "/resourceRecords"
    logger = logging.getLogger()
    logging.debug(f"link {link}")
    url = f"https://{session.server}{link}"
    response = requests.post(
        url, headers=session.auth_header, json=msg, timeout=session.timeout
    )
    if response.status_code != 201:
        print(f"Failed: {response.status_code} Error")
        print(response.text)
        return
    data = response.json()
    data=session.removelinks(data)
    print(f"Success, created {data}")
    return


def parse(description=""):
    """Set up common argparse arguments for BlueCat API"""
    config = BAMv2.argparsecommon(description)

    config.add_argument(
        "host", help="fully qualified hostname", nargs='?', default=None
    )
    config.add_argument("ip", help="IP address", nargs='?', default=None)
    config.add_argument(
        "--ext",
        help="IP is an external IP (will create a Generic Record)",
        action='store_true',
    )
    config.add_argument(
        "-f",
        "--file",
        help="CSV file to process; Line format: HOSTNAME,IPADDRESS",
        type=argparse.FileType("r"),
        default=sys.stdin,
        metavar="filename.csv",
    )
    return config


def main():
    """Add Host Record"""
    description = "Add Host Record"
    config = parse(description)
    args = config.parse_args()

    logger = logging.getLogger()
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s")
    logger.setLevel(args.logging)

    configuration_name = args.configuration_name
    view_name = args.view_name
    filename = args.file
    host = args.host
    ip = args.ip

    if not (configuration_name and view_name):
        print("--config and --view must be defined")
        config.print_help()
        sys.exit(1)

    session = BAMv2(args.server, args.username, args.password, args.timeout)

    session.get_config_and_view(configuration_name, view_name)

    if filename != sys.stdin:
        if ip or host:
            print("--file cannot be used with --host and --ip, use one or other")
            config.print_help()
            sys.exit(1)
        else:
            input_lines = csv.reader(filename)
            for line in input_lines:
                mylen=len(line)
                print(f"len {mylen}, line read:{line}")
                dic = {
                    "host": line[0],
                    "ip": line[1],
                    "ext": args.ext,
                    "view": view_name,
                    "cfg": configuration_name,
                }

                add_host_record(dic, session)
    elif not (host and ip):
        print("either --file OR both --host and --ip must be specified")
        config.print_help()
        sys.exit(1)
    else:
        dic = {
            "host": args.host,
            "ip": args.ip,
            "ext": args.ext,
            "view": view_name,
            "cfg": configuration_name,
        }
        add_host_record(dic, session)


if __name__ == "__main__":
    main()
