#!/usr/bin/env python
"""add_DHCP_Reserved.py [--server servername] -f <filename>
OR
add_DHCP_Reserved.py --ip IP --mac MAC --ipname DESC --hostname NAME --view VIEW
(other options available)
"""

import csv
import sys
import logging
import argparse
import re
import requests
from bamv2 import BAMv2


def add_dhcp_reserved(dic, session):
    """Add DHCP_RESERVED"""

    print(f"Adding DHCP_RESERVED for {dic['ip_addr']}", end=" ")

    # if MAC Address is in Cisco format, convert to a format that BlueCat understands
    # (in this case, just remove the puncutuation)
    string = re.search(
        r"(?P<part1>[0-9a-fA-F]{4})[.](?P<part2>[0-9a-fA-F]{4})[.](?P<part3>[0-9a-fA-F]{4})",
        dic["mac"],
    )
    if string:
        dic["mac"] = (
            string.group("part1") + string.group("part2") + string.group("part3")
        )

    # find this IP Address, if it exists
    address_url = f"{session.mainurl}/addresses?filter=address:eq('{dic['ip_addr']}')"
    response = requests.get(
        address_url, headers=session.auth_header, timeout=session.timeout
    )

    # expect a 200 response, but with zero data if it does not exist yet.
    if not response.status_code == 200:
        print(f"Failed: {response.status_code} Error")
        logging.debug(response.text)
        return
    data = response.json()
    logging.debug(data)

    if not data["data"]:
        # IP does not exist, so create it
        # now search for the network to add the IP Address
        url = f"{session.mainurl}/networks?filter=range:contains('{dic['ip_addr']}') and configuration.name:eq('{session.configuration_name}')"
        response = requests.get(
            url, headers=session.auth_header, timeout=session.timeout
        )
        if response.status_code != 200:
            print(f"Failed: {response.status_code} Error")
            logging.debug(response.text)
            return
        data = response.json()
        logging.debug(data)
        url = data["data"][0]["_links"]["addresses"]["href"]
        url = f"https://{session.server}{url}"
        msg = {
            "type": "IPv4Address",
            "name": dic["ip_name"],
            "state": "DHCP_RESERVED",
            "address": dic["ip_addr"],
            "macAddress": {"address": dic["mac"]},
            'userDefinedFields': {'Assigned_Date': dic['assigned'], 'Requested_by': dic['requested']},
        }
        # can create host record at the same time
        if dic["host"]:
            msg["resourceRecords"] = [
                {
                    "type": "HostRecord",
                    "absoluteName": dic["host"],
                    "views": [
                        {
                            "id": session.view_id,
                            "type": "View",
                            "name": dic["view"],
                            'userDefinedFields': {'Assigned_Date': dic['assigned'], 'Requested_by': dic['requested']},
                        }
                    ],
                }
            ]
        # create address, optional hostname, and MAC Address (if MAC Address does not exist)
        response = requests.post(
            url, headers=session.auth_header, json=msg, timeout=session.timeout
        )
        if response.status_code != 201:
            print(f"Failed: {response.status_code} Error")
            logging.debug(response.text)
            return
        print("Success.")
        data = response.json()
        print(data)
        return 

    if data["count"] == 1:
        ip_obj = data["data"][0]
        print("Update existing: ", ip_obj)
        update_helper(session, ip_obj, dic)


def update_helper(session, ip_obj, dic):
    """Update when an address already exists"""
    addr_id = ip_obj["id"]
    url = f"{session.mainurl}/addresses/{addr_id}"
    msg = {
        "type": "IPv4Address",
        "name": dic["ip_name"],
        "state": "DHCP_RESERVED",
        "address": dic["ip_addr"],
        "macAddress": {"address": dic["mac"]},
    }
    # attempting to create host record here does NOT work, this is ignored
    if dic["host"]:
        msg["resourceRecords"] = [
            {
                "type": "HostRecord",
                "absoluteName": dic["host"],
                "views": [
                    {
                        "id": session.view_id,
                        "type": "View",
                        "name": dic["view"],
                    }
                ],
            }
        ]
    # updates address and creates MAC Addresss if it does not exist
    logging.debug(f"PUT data: {msg}")
    response = requests.put(
        url, headers=session.auth_header, json=msg, timeout=session.timeout
    )
    if response.status_code == 200:
        print("Update succeeded.")
    else:
        print(f"Update failed: {response.status_code} Error")
        logging.debug(response.text)
    # attempt to add host record
    #if dic["host"]:
    #    # check existing host record (in ip obj already pulled?)



def parse(description="add/update/overwrite DHCP Reserved"):
    """Set up common argparse arguments for BlueCat API"""
    config = BAMv2.argparsecommon(description)

    config.add_argument("--ip", "-i", "-a", "--address", help="ip address")
    config.add_argument(
        "--mac", "-m", "--hw", "--hardware", help="Interface MAC or HW address"
    )
    config.add_argument("--ipname", help="optional - name for the IP object")
    config.add_argument(
        "--host", "--hostname", "--fqdn", "--dns", "-d", help="optional - hostname"
    )
    config.add_argument(
        "-f",
        "--file",
        help="CSV file to process; Line format: IP,MAC,DESCRIPTION,HOSTNAME,VIEWNAME,"
        +"ASSIGNEDDATE,REQUESTEDBY   Only IP and MAC are required, ASSIGNEDDATE must be"
        +" in ISO 8601 format like 2025-06-23T00:00Z",
        type=argparse.FileType("r"),
        default=sys.stdin,
        metavar="filename.csv",
    )
    config.add_argument("--assigned",help="optional Assigned Date in ISO 8601 format like 2025-06-23T00:00Z")
    config.add_argument("--requested",help="optional Requested By")
    return config


def main():
    """Execute program"""
    description = "Add DHCP Reserved for an ip address"
    config = parse(description)
    args = config.parse_args()

    logger = logging.getLogger()
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s")
    logger.setLevel(args.logging)

    configuration_name = args.configuration
    view_name = args.view
    filename = args.file
    ip_addr = args.ip
    mac = args.mac
    assigned=args.assigned
    requested=args.requested

    if not (configuration_name and view_name):
        print("--config and --view must be defined")
        config.print_help()
        sys.exit(1)

    #session = BAMv2(args.server, args.username, args.password, args.timeout)
    with BAMv2(args.server, args.username, args.password, args.timeout) as session:

        session.get_config_and_view(configuration_name, view_name)

        if filename != sys.stdin:
            if ip_addr or mac:
                print("--file cannot be used with --ip and --mac, use one or other")
                config.print_help()
                sys.exit(1)
            else:
                input_lines = csv.reader(filename)
                for line in input_lines:
                    linelen=len(line)
                    if linelen < 2:
                        print(f"ERROR - line must have at least 'MAC-Address,IP' - skipping: {line}")
                        continue
                    dic = {
                        "ip_addr": line[0],
                        "mac": line[1],
                        "ip_name": line[2] if linelen > 2 else None,
                        "host": line[3] if linelen > 3 else None,
                        "view": line[4] if linelen > 4 else None,
                        "assigned": line[5] if linelen > 5 else None,
                        "requested": line[6] if linelen > 6 else None,
                    }
                    add_dhcp_reserved(dic, session)
        elif not (ip_addr and mac):
            print("either --file OR both ( --ip and --mac ) must be specified")
            config.print_help()
            sys.exit(1)
        else:
            dic = {
                "ip_addr": ip_addr,
                "mac": mac,
                "ip_name": args.ipname,
                "host": args.host,
                "view": view_name,
                "assigned": assigned,
                "requested": requested,
            }
            add_dhcp_reserved(dic, session)


if __name__ == "__main__":
    main()
