#!/usr/bin/env python
"""add_alias_cname_record.py [--server servername] -f <filename>
OR
add_alias_cname_record.py --hostname NAME --dest NAME --view VIEW
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


def add_alias_cname_record(dic, session):
    """Add Alias(CNAME) Record"""

    #print(f"Adding Alias(CNAME) Record for {dic['host']}", end=" ")

    #print('')

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

    if dic['ext']:  # if external host destination
        add_alias_ext(dic, session, zoneobj, remainder)
        return

    # find the destination
    dest=dic["dest"]
    fieldspec="id,type,name,absoluteName,configuration.id,configuration.name,linkedRecord.id,linkedRecord.absoluteName,userDefinedFields.source"
    destresp=session.get_resource_records(filter=f"absoluteName:eq('{dest}') and configuration.name:eq('{session.configuration_name}')",
                            fields=fieldspec)
    if destresp['count'] > 1:
        print(f"ERROR - found multiple records {destresp}")
        return None
    elif destresp['count'] == 0:
        print(f"ERROR - destination {dest} not found")
        return None
    destobj= destresp['data'][0]
    logging.debug(f"found dest {destobj}")
    create_alias_record(session,zoneobj,remainder,destobj)


def create_alias_record(session,zoneobj,remainder,destobj):
    '''once destination object is found, create the record'''
    link = "/api/v2/zones/" + str(zoneobj['id']) + "/resourceRecords"
    logging.debug(f"link {link}")

    url = f"https://{session.server}{link}"
    msg = {
        "type": "AliasRecord",
        "name": remainder,
        "linkedRecord": {
            "id": destobj['id'],
            "type": destobj['type']
        }
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


def add_alias_ext(dic, session, zoneobj, remainder):
    '''Add alias(CNAME) pointing to External Host Record, 
    create the external record if needed'''

    # find the destination
    dest=dic["dest"]
    fieldspec="id,type,name,absoluteName,configuration.id,configuration.name,linkedRecord.id,linkedRecord.absoluteName,userDefinedFields.source"
    destresp=session.get_resourceRecords(filter=f"absoluteName:eq('{dest}')",
                            fields=fieldspec) 
    if destresp['count'] > 1:
        print(f"ERROR - found multiple records {destresp}")
        return None
    elif destresp['count'] == 0:    # if not found, create it!
        #print(f"ERROR - destination {dest} not found")

        # find the special zone for external hosts
        url=f"{session.mainurl}/zones?filter=type:eq(\"ExternalHostsZone\") and view.name:eq(\"{dic['view']}\") and configuration.name:eq(\"{dic['cfg']}\")&fields=id"
        response = requests.get(
            url, headers=session.auth_header, timeout=session.timeout
        )
        if response.status_code != 200:
            print(f"Failed to find ExternalHostsZone for view {dic['view']} and configuration {dic['cfg']}")
            print(f"status code {response.status_code}, {response.text}")
            return None
        resp=response.json()
        extid=resp['data'][0]['id']

        # create External Host record
        url=f"{session.mainurl}/zones/{extid}/resourceRecords"
        msg={
            "type": "ExternalHostRecord",
            "name": dest
        }
        response=requests.post(
            url, headers=session.auth_header, json=msg, timeout=session.timeout
        )
        if response.status_code != 201:
            print(f"Failed to create Alias(CNAME) for {dic["host"]} to {dest}, {response.status_code} {response.text}")
            return None
        #print(f"{response.json()}")
        destobj=response.json()
    else:
        destobj=destresp['data'][0]
    logging.debug(f"found dest {destobj}")

    create_alias_record(session,zoneobj,remainder,destobj)
    return


def parse(description=""):
    """Set up common argparse arguments for BlueCat API"""
    config = BAMv2.argparsecommon(description)

    config.add_argument(
        "host", help="fully qualified hostname", nargs='?', default=None
    )
    config.add_argument("dest", help="destination hostname", nargs='?', default=None)
    config.add_argument(
        "--ext",
        help="destination is an external host (will create the external host if needed)",
        action='store_true',
    )
    config.add_argument(
        "-f",
        "--file",
        help="CSV file to process; Line format: HOSTNAME,DESINATIONNAME",
        type=argparse.FileType("r"),
        default=sys.stdin,
        metavar="filename.csv",
    )
    return config


def main():
    """Add Alias(CNAME) Record"""
    description = "Add Alias(CNAME) Record"
    config = parse(description)
    args = config.parse_args()

    logger = logging.getLogger()
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s")
    logger.setLevel(args.logging)

    configuration_name = args.configuration
    view_name = args.view
    filename = args.file
    host = args.host
    dest = args.dest

    if not (configuration_name and view_name):
        print("--config and --view must be defined")
        config.print_help()
        sys.exit(1)

    session = BAMv2(args.server, args.username, args.password, args.timeout)

    session.get_config_and_view(configuration_name, view_name)

    if filename != sys.stdin:
        if dest or host:
            print("--file cannot be used with --host and --dest, use one or other")
            config.print_help()
            sys.exit(1)
        else:
            input_lines = csv.reader(filename)
            for line in input_lines:
                mylen=len(line)
                print(f"len {mylen}, line read:{line}")
                dic = {
                    "host": line[0],
                    "dest": line[1],
                    "ext": args.ext,
                    "view": view_name,
                    "cfg": configuration_name,
                }

                add_alias_cname_record(dic, session)
    elif not (host and dest):
        print("either --file OR both --host and --dest must be specified")
        config.print_help()
        sys.exit(1)
    else:
        dic = {
            "host": args.host,
            "dest": args.dest,
            "ext": args.ext,
            "view": view_name,
            "cfg": configuration_name,
        }
        add_alias_cname_record(dic, session)


if __name__ == "__main__":
    main()
