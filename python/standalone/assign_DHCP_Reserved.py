#!/usr/bin/env python
"""assign_DHCP_Reserved.py -f <filename>
OR
assign_DHCP_Reserved.py IP MAC [ HOSTNAME ]
(other options available)
"""

import sys
import logging
import argparse
import re
import requests
import os
from datetime import datetime, timezone


def assign_dhcp_reserved(dic, session):
    """Assign DHCP_RESERVED"""

    print(f"Assigning DHCP_RESERVED for {dic['ip_addr']}", end=" ")

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
    network_url = f"{session.mainurl}/addresses?filter=address:eq('{dic['ip_addr']}')"
    response = requests.get(network_url, headers=session.auth_header)

    # expect a 200 response, but likely zero data if it does not exist yet.
    if not response.status_code == 200:
        print(f"Failed: {response.status_code} Error")
        logging.debug(response.text)
        return
    data = response.json()
    logging.debug(data)

    if not data["data"]:
        # now search for the network to add the IP Address
        response = session.get(
            f"/networks?filter=range:contains('{dic['ip_addr']}') "
            f"and configuration.name:eq('{session.configuration_name}')"
        )
        if response.status_code != 200:
            print(f"Failed: {response.status_code} Error, {response.text}")
            logging.debug(response.text)
            return
        data = response.json()
        logging.debug(data)

        ###### add if here???

        url = data["data"][0]["_links"]["addresses"]["href"]
        url = f"https://{session.server}{url}"
        msg = {
            "type": "IPv4Address",
            "name": dic["ip_name"],
            "state": "DHCP_RESERVED",
            "address": dic["ip_addr"],
            "macAddress": {"address": dic["mac"]},
            "userDefinedFields": {
                "Assigned_Date": dic["assigned"],
                "Requested_by": dic["requested"],
            },
        }
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
                            "userDefinedFields": {
                                "Assigned_Date": dic["assigned"],
                                "Requested_by": dic["requested"],
                            },
                        }
                    ],
                }
            ]
        response = requests.post(url, headers=session.auth_header, json=msg)
        if response.status_code != 201:
            print(f"Failed: {response.status_code} Error, {response.text}")
            logging.debug(response.text)
            return
        print("Success.")
        data = response.json()
        # print(data)   # should add verbose option to print this
        return

    print("Already Exists.", end=" ")
    update_helper(session, data["data"][0]["id"], dic)


def update_helper(session, addr_id, dic):
    """Update when an address already exists"""
    url = f"{session.mainurl}/addresses/{addr_id}"
    msg = {
        "type": "IPv4Address",
        "name": dic["ip_name"],
        "state": "DHCP_RESERVED",
        "address": dic["ip_addr"],
        "macAddress": {"address": dic["mac"]},
    }
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
    logging.debug(f"PUT data: {msg}")
    response = requests.put(url, headers=session.auth_header, json=msg)
    if response.status_code == 200:
        print("Update succeeded.")
    else:
        print(f"Update failed: {response.status_code} Error")
        logging.debug(response.text)
    # attempt to add host record
    # if dic["host"]:
    #    # check existing host record


def parse(description):
    """Set up common argparse arguments for BlueCat API"""
    config = BAMv2.argparsecommon(description)

    config.add_argument(
        "data",
        nargs="*",
        help="optional data to add, if not using --file,"
        " include IP MAC and optionally HOSTNAME, in any order, separated by spaces, tabs, commas, or whatever, for example: "
        "'1.2.3.4  a:b:c:d:e:f     myhost.mydomain.com' OR "
        "'a:b:c:d:e:f,1.2.3.4' OR "
        "'myhost.mydomain.com/a:b:c:d:e:f/1.2.3.4'",
    )
    config.add_argument("-i", "--ip", help="ip address")
    config.add_argument("-m", "--mac", help="Interface MAC or HW address")
    config.add_argument("--ipname", help="optional - name for the IP object")
    config.add_argument("-d", "--hostname", help="optional hostname (domainname)")
    config.add_argument(
        "-n",
        "--networkip",
        help="optional network address to find next available IP Address",
    )
    config.add_argument(
        "-f",
        "--file",
        help="file to process with lines like 'data' above",
        type=argparse.FileType("r"),
        default=sys.stdin,
        metavar="filename",
    )
    config.add_argument(
        "--assigned",
        help="optional Assigned Date in ISO 8601 format like 2025-06-23T00:00Z",
    )
    config.add_argument("--requested", help="optional Requested By")
    return config


def main():
    """Execute program"""
    description = "Assign DHCP Reserved for an IP Address"
    config = parse(description)
    args = config.parse_args()

    logger = logging.getLogger()
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s")
    logger.setLevel(args.logging.upper())

    configuration_name = args.configuration_name
    view_name = args.view_name
    filename = args.file
    ip_addr = args.ip
    mac = args.mac
    data = args.data

    if not (configuration_name and view_name):
        print("--config and --view must be defined")
        config.print_help()
        sys.exit(1)

    with BAMv2(
        args.server,
        args.username,
        args.password,
    ) as session:

        session.get_config_and_view(configuration_name, view_name)

        if args.networkip:
            # find the network

            url = f"{session.mainurl}/networks?filter=configuration.name:eq('{session.configuration_name}') and range:contains('{args.networkip}')"
            response = requests.get(url, headers=session.auth_header)
            if response.status_code != 200:
                print(f"Failed: {response.status_code} Error, {response.text}")
                logging.debug(response.text)
                sys.exit(1)
            data = response.json()
            logging.debug(data)
            if not data["data"]:
                print(
                    f"ERROR - network containing {args.networkip} not found in configuration {session.configuration_name}"
                )
                sys.exit(1)
            args.network_id = data["data"][0]["id"]
        else:
            args.network_id = None

        if filename != sys.stdin:
            if ip_addr or mac:
                print(
                    "--file cannot be used with --ip and --mac or data, use one or other"
                )
                config.print_help()
                sys.exit(1)
            else:
                for line in filename:
                    add_line(args, line, session)
        elif not (data or (ip_addr and mac)):
            print("either --file OR data OR both --ip and --mac must be specified")
            config.print_help()
            sys.exit(1)
        else:
            line = " ".join(args.data)
            add_line(args, line, session)


def add_line(args, line, session):
    """Add a line of data, either from the file or from the command line arguments"""
    logger = logging.getLogger()
    logger.debug(f"Processing line: {line}")
    if args.ip:
        ip = args.ip
    else:
        s = re.search(r"((?:\d{1,3}\.){3}\d{1,3})($|[^\d])", line)
        if s:
            ip = s.group(1)
        elif args.networkip:
            # find next available IP Address if given a network
            ip = find_next_ip(args, session)
            if ip:
                logger.debug(f"Found next available IP Address: {ip}")
            else:
                print(
                    f"ERROR - no available IP Address found in network {args.networkip}"
                )
                return
        else:
            print(f"ERROR - no IP Address found in line: {line}")
            return
    if args.mac:
        mac = args.mac
    else:
        s = re.search(
            r"""(^|[^-.:0-9a-fA-F])((?:[0-9a-fA-F]{1,2}[-:.]){5}
                [0-9a-fA-F]{1,2}|[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{4}
                [.]){2}[0-9a-fA-F]{4})($|[^-.:0-9a-fA-F-])""",
            line,
            re.X,
        )
        if s:
            mac = canonical_mac(s.group(2))
        else:
            print(f"ERROR - no MAC Address found in line: {line}")
            return
    if args.hostname:
        host = args.hostname
    else:
        s = re.search(r"(((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63})", line)
        if s:
            host = s.group(1).lower()
        else:
            host = None
    dic = {
        "ip_addr": ip,
        "mac": mac,
        "ip_name": args.ipname,
        "host": host,
        "view": args.view_name,
        "assigned": args.assigned,
        "requested": args.requested,
    }
    assign_dhcp_reserved(dic, session)


def find_next_ip(args, session):
    """Find the next available IP Address in a network"""
    url = f"https://{session.server}/api/v2/networks/{args.network_id}/addresses?filter=state:'UNASSIGNED'&limit=1"
    response = requests.get(url, headers=session.auth_header)
    if response.status_code != 200:
        print(f"Failed: {response.status_code} Error, {response.text}")
        logging.debug(response.text)
        return None
    resp = response.json()
    logging.debug(resp)
    if not resp["data"]:
        return None
    return resp["data"][0].get("address")


def canonical_mac(mac):
    """reformat mac address to be sure there are always two hex digits"""
    hex_list = re.split(r"[-:.]", mac)
    if len(hex_list) == 1:
        hex_list = re.search(r"^(..)(..)(..)(..)(..)(..)$", mac).groups()
    out_list = []
    for h in hex_list:
        if len(h) == 1:
            h = "0" + h
        # h = format(h, "02x")
        out_list.append(h.lower())
    hexout = ":".join(out_list)
    return hexout


class BAMv2(requests.Session):  # pylint: disable=R0902
    """subclass requests and redefine requests.request to
    a simpler BlueCat interface"""

    # Note that this inherits functions from requests like:
    # get
    # post
    # put
    # delete

    def __init__(
        self,
        server=None,
        username=None,
        password=None,
        configuration_name=None,
        view_name=None,
        **kwargs,
    ):
        """login to BlueCat server API, get token, set header"""
        self.username = username
        self.password = password
        self.configuration_id = None
        self.configuration_name = configuration_name
        self.view_id = None
        self.view_name = view_name
        if not (server and username and password):
            print("server, username, and password are required.\n")
            raise requests.RequestException
        self.server = server
        logging.debug(
            f"server: {self.server} username: {self.username} "
            f"configuration_name: {self.configuration_name} "
            f"view_name: {self.view_name}"
        )
        self.mainurl = f"https://{server}/api/v2"
        logging.info("url: %s", self.mainurl)

        requests.Session.__init__(self)
        self.login()

    def __exit__(self, *args):
        self.logout()

    def login(self):
        """login, get token"""
        try:
            auth_url = f"{self.mainurl}/sessions"
            credentials = {"username": self.username, "password": self.password}
            response = requests.post(auth_url, json=credentials)
        except requests.exceptions.ConnectionError as errormsg:
            print("failed to login: ", errormsg)
            raise requests.exceptions.ConnectionError
        if response.status_code != 201:
            print(response.json(), file=sys.stderr)
            raise requests.HTTPError

        response_data = response.json()
        self.basic_auth_credentials = response_data["basicAuthenticationCredentials"]

        # Links are included in JSON representations
        # when the media type application/hal+json or */* is set in the Accept header of the HTTP request.
        self.auth_header = {
            "accept": "application/hal+json",
            "Authorization": f"Basic {self.basic_auth_credentials}",
            "Content-Type": "application/hal+json",
        }

        logger = logging.getLogger()
        logger.debug(f"{self.auth_header}")

    def logout(self):
        """log out of BlueCat server, return nothing"""
        msg = {"state": "LOGGED_OUT"}
        logout_url = self.mainurl + "/sessions/current"
        header = self.auth_header
        header["Content-Type"] = "application/merge-patch+json"
        self.patch(logout_url, headers=header, json=msg)

    @staticmethod
    def argparsecommon(description=""):
        """Set up common argparse arguments for BlueCat API"""
        # usage: config = bluecat_bam.BAM.argparsecommon()
        config = argparse.ArgumentParser(description=description)
        config.add_argument(
            "--server",
            "-s",
            default=os.getenv("BLUECAT_SERVER"),
            help="BlueCat Address Manager hostname",
        )
        config.add_argument(
            "--username",
            "-u",
            default=os.getenv("BLUECAT_USERNAME"),
        )
        config.add_argument(
            "--password",
            "-p",
            default=os.getenv("BLUECAT_PASSWORD"),
            help="password in environment, should not be on command line",
        )
        config.add_argument(
            "--configuration_name",
            "--cfg",
            help="BlueCat Configuration name",
            default=os.getenv("BLUECAT_CONFIGURATION"),
        )
        config.add_argument(
            "--view_name", help="BlueCat View", default=os.getenv("BLUECAT_VIEW")
        )
        config.add_argument(
            "--logging",
            "-l",
            help="log level, default WARNING (30),"
            + "caution: level DEBUG(10) or less "
            + "will show the password in the login call",
            default=os.getenv("BLUECAT_LOGGING", "WARNING"),
        )
        return config

    def get(self, urlpath, **kwargs):
        """wrapper for requests.get with url prefix and error handling"""
        logging.debug(f"Using {self.mainurl} GET {urlpath} with kwargs {kwargs}")
        url = f"{self.mainurl}{urlpath}"
        header = self.auth_header
        kwargs["headers"] = header
        response = requests.get(url, **kwargs)
        if response.status_code != 200:
            print(f"Failed: {response.status_code} Error")
            logging.debug(response.text)
        return response

    def get_config_and_view(self, configuration_name, view_name=None):
        """get configuration_id and view_id"""
        # usage: (configuration_id, view_id) =
        #    conn.get_config_and_view(configuration_name, view_name)
        # or for just configuration:
        # (configuration_id, _) = conn.get_config_and_view(configuration_name)

        configuration_url = f"{self.mainurl}/configurations?fields=id,name&filter=name:eq('{configuration_name}')"
        response = requests.get(configuration_url, headers=self.auth_header)
        if response.status_code == 200:
            configurations = response.json()
            # print(configurations)
            logging.info("Configuration ID: %s", {configurations["data"][0]["id"]})
            self.configuration_id = configurations["data"][0]["id"]
            self.configuration_name = configurations["data"][0]["name"]
        else:
            print("Failed to retrieve configuration IDs.")
            logging.debug(response.text)

        if view_name:
            view_url = (
                f"{self.mainurl}/views?fields=id,name&filter=name:eq('{view_name}')"
            )
            response = requests.get(view_url, headers=self.auth_header)
            if response.status_code == 200:
                views = response.json()
                logging.info("View ID: %s", {views["data"][0]["id"]})
                self.view_id = views["data"][0]["id"]
                self.view_name = views["data"][0]["name"]
            else:
                print("Failed to retrieve view IDs.")
                logging.debug(response.text)
        else:
            self.view_id = None
        return self.configuration_id, self.view_id


if __name__ == "__main__":
    main()
