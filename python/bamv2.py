#!/usr/bin/env python
"""This is our bam version2 API"""
import os
import sys
import urllib.parse
from datetime import datetime, timezone
import logging
import argparse
import re
import time
import requests
from ipaddress import ip_address, ip_network


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
        timeout=None,
        max_retries=None,
        configuration_name=None,
        view_name=None,
        links=None,
        **kwargs
    ):
        """login to BlueCat server API, get token, set header"""
        self.username = username
        self.password = password
        self.timeout = timeout
        self.configuration_id = None
        self.configuration_name = configuration_name
        self.view_id = None
        self.view_name = view_name
        self.links = links
        # self.parentviewcache = {}  # zoneid: viewid
        if not (server and username and password):
            print("server, username, and password are required.\n")
            raise requests.RequestException
        self.server = server
        logging.debug(f"server: {self.server} username: {self.username} timeout: {self.timeout} "
                      f"links: {self.links} configuration_name: {self.configuration_name} "
                      f"view_name: {self.view_name}")
        self.mainurl = f"https://{server}/api/v2"
        logging.info("url: %s", self.mainurl)

        requests.Session.__init__(self)
        if max_retries:
            adapter = requests.adapters.HTTPAdapter(max_retries=max_retries)
            url_prefix = self.mainurl.split("://", 1)[0] + "://"
            self.mount(url_prefix, adapter)
        self.login()

        # set up compiled patterns once at start for later .match
        # IP patterns are not fully detailed, but we then check with ipaddress
        # Tested at regex101.com
        # for a full regex, see https://regex101.com/r/5CZpb6/1
        self.ip6_range_pattern = re.compile(
            r"^(?P<start>[:0-9a-fA-F]+)"
            r"-(?P<end>[:0-9a-fA-F]+)$"
        )
        """test cases for ip6_range regex:
        2001:db8::1-2001:db8::ffff
        ::1-::ffff
        """
        self.ip4_range_pattern = re.compile(
            r"^(?P<start>[.0-9]+)"
            r"-(?P<end>[.0-9]+)$"
        )
        """test cases for ip4_range regex:
        1.2.3.4-255.255.255.255
        10.10.10.10-10.10.20.20
        """
        self.ip4_pattern = re.compile(
            r"^(?:\d{1,3}\.){3}\d{1,3}$"
        )
        """ test cases for ip4 regex
        1.2.3.4
        4.33.22.111
        10.10.20.20
        255.255.255.255
        """
        self.ip6_pattern = re.compile(
            r"^:{0,2}(?:[0-9a-fA-F]{1,4}(?:\.|::?)){0,9}[0-9a-fA-F]{1,4}:{0,2}$"
        )
        """ test cases  for ip6 regex
        a:b:c:d:e:F:1:2
        2001:db8::1
        ::1
        """
        self.ip4_cidr_pattern = re.compile(
            r"^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
            r"\/(?P<prefix>\d{1,2})$"
        )
        """ test cases for ip4 CIDR regex
        10.0.0.0/8
        35.1.22.128/25
        10.10.0.0/16
        255.255.255.255/32
        """
        self.ip6_cidr_pattern = re.compile(
            r"^(?P<ip>:{0,2}(?:[0-9a-fA-F]{1,4}(?:\.|::?)){0,9}[0-9a-fA-F]{1,4}:{0,2})"
            r"\/(?P<prefix>\d{1,3})$"
        )
        """ test cases for ip6 CIDR regex
        2001:db8::1/64
        ::1/128
        """
        self.mac_pattern = re.compile(
            r"^((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}|"
            "[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{4}[.]){2}[0-9a-fA-F]{4})$"
        )
        """ test cases for MAC regex
        00:11:22:33:44:55
        00-11-22-33-44-55
        001122334455
        0011.2233.4455
        """
        self.fqdn_pattern = re.compile(r"^[a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)+$")
        """ test cases for FQDN regex
        example.com
        sub.example.com
        example.co.uk
        """
        self.id_pattern = re.compile(r"^\d+$")
        """ test cases for ID regex
        12345
        67890
        """

    def __exit__(self, *args):
        self.logout()

    def login(self):
        """login, get token"""
        try:
            auth_url = f"{self.mainurl}/sessions"
            credentials = {"username": self.username, "password": self.password}
            response = requests.post(auth_url, json=credentials, timeout=self.timeout)
        except requests.exceptions.ConnectionError as errormsg:
            print("failed to login: ", errormsg)
            raise requests.exceptions.ConnectionError
        if response.status_code != 201:
            print(response.json(), file=sys.stderr)
            raise requests.HTTPError

        start_time = datetime.now(timezone.utc)

        response_data = response.json()
        # self.token = response_data["apiToken"]  # old version, 9.5.x and below
        self.basic_auth_credentials = response_data[
            "basicAuthenticationCredentials"
        ]  # required in 9.6
        end_time = datetime.fromisoformat(
            response_data["apiTokenExpirationDateTime"].replace("Z", "+00:00")
        )
        duration = end_time - start_time
        logging.info(
            "API basic_auth_credentials: %s, start time: %s, end time: %s, duration: %s",
            self.basic_auth_credentials,
            start_time,
            end_time,
            duration,
        )
        # logging.info(self.basic_auth_credentials)

        # Links are included in JSON representations
        # when the media type application/hal+json or */* is set in the Accept header of the HTTP request.
        self.auth_header_links = {
            "accept": "application/hal+json",
            "Authorization": f"Basic {self.basic_auth_credentials}",
            "Content-Type": "application/hal+json",
        }

        # A media type of application/json will exclude the _links field in resource representations.
        self.auth_header_nolinks = {
            "accept": "application/json",
            "Authorization": f"Basic {self.basic_auth_credentials}",
            "Content-Type": "application/hal+json",
        }

        self.auth_header = self.auth_header_links
        if self.links is not False:
            self.auth_header_default = self.auth_header_links
        else:
            self.auth_header_default = self.auth_header_nolinks


        logging.debug(f"{self.links} {self.auth_header_default}")

    def logout(self):
        """log out of BlueCat server, return nothing"""
        msg = {"state": "LOGGED_OUT"}
        logout_url = self.mainurl + "/sessions/current"
        header = self.auth_header_nolinks
        header["Content-Type"] = "application/merge-patch+json"
        self.patch(logout_url, headers=header, json=msg, timeout=self.timeout)

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
        config.add_argument(
            "--timeout",
            "-t",
            type=int,
            default=30,
            help="Timeout for the requests (in seconds)",
        )
        config.add_argument(
            "--links",
            default=True,
            action=argparse.BooleanOptionalAction,
            help="option --no-links will remove links from returned objects in some cases",
        )
        return config


    def get(self, url, links=None, **kwargs):
        """wrapper for requests.get with url prefix and error handling"""
        logging.debug(f"GET {url} with kwargs {kwargs}")
        if links is None:
            links = self.links
        if links:
            header = self.auth_header_links
        else:
            header = self.auth_header_nolinks
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
        response = requests.get(
            configuration_url, headers=self.auth_header_nolinks, timeout=self.timeout
        )
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
            response = requests.get(
                view_url, headers=self.auth_header_nolinks, timeout=self.timeout
            )
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

    @staticmethod
    def removelinks(obj):
        """return object with _links removed in first two levels"""
        # caller should use something like:
        #  obj = response.json()
        # removelinks(obj)

        # if isinstance(obj,list):

        # for part in obj['data']:
        part = obj
        if "_links" in part:
            del part["_links"]
        for key in part:
            val = part[key]
            # print(f"key {key} val {val}")
            if isinstance(val, dict) and "_links" in val:
                del val["_links"]
        return obj

    def get_deployment_roles(
        self, identifier, resource_type=None, deployment_type=None, inherited=None
    ):
        """Get deployment roles"""
        logging.debug(f"Getting deployment roles for {identifier}")

        obj_list = self.get_obj_list(identifier, resource_type)
        logging.debug(f"obj_list: {obj_list}")

        '''
        if resource_type is None:
            resource_type,_ = self.match_type(identifier,None)
            #resource_type = self.detect_resource_type(identifier)
        logging.debug(resource_type)

        if resource_type == "zone":
            url = f"{self.mainurl}/zones?filter=absoluteName:eq('{identifier}')"
        elif resource_type == "block":
            url = f"{self.mainurl}/blocks?filter=range:eq('{identifier}')"
        elif resource_type == "network":
            url = f"{self.mainurl}/networks?filter=range:eq('{identifier}')"
        else:
            print(f"Resource type {resource_type} not supported.")
            return None

        response = requests.get(url, headers=self.auth_header_nolinks, timeout=self.timeout)

        if response.status_code != 200:
            print(f"Failed: {response.status_code} Error")
            logging.debug(response.text)

        data = response.json()
        '''

        if not obj_list:
            print("Not found.")
            return None
        elif len(obj_list) > 1:
            print(f"Multiple objects found: {obj_list}")
            return None

        resource_id = obj_list[0]["id"]
        mylink = obj_list[0].get("_links", {}).get("self", {}).get("href", "")
        resource_type =  mylink.split("/")[-2]
        #resource_type = resource_type + "s"

        if deployment_type and resource_type != "zones":
            url = (
                f"{self.mainurl}/{resource_type}/{resource_id}/deploymentRoles"
                f"?filter=type:eq('{deployment_type}')"
                f"&fields=embed(interfaces)"
            )
        else:
            url = (
                f"{self.mainurl}/{resource_type}/{resource_id}/deploymentRoles"
                f"?fields=embed(interfaces)"
            )

        response = requests.get(url, headers=self.auth_header_default, timeout=self.timeout)
        data = response.json()
        dic = {
            "id": resource_id,
            "resource_type": resource_type,
            "names": [],
            "role_ids": [],
        }
        logging.debug(data)
        for role in data["data"]:
            logging.debug(role)
            if role.get("_inheritedFrom"):
                logging.debug(f"inherited")
                if not inherited:   # skip inherited unless 'inherited' flag is true
                    continue
            logging.debug(f"\t{role['type']} {role['roleType']}")
            for interface in role["_embedded"]["interfaces"]:
                logging.debug(f"\t\t{interface['name']} {interface['server']['name']}")
                dic["names"].append(interface["name"])
                dic["role_ids"].append(role["id"])
                #dic["names"].append(interface["server"]["name"])
                #dic["role_ids"].append(role["id"])
        return dic

    # Define a set of "is_TYPE" functions
    # see comments where the patterns are defined above

    def is_ip4_range(self, object_ident):
        """Detect if the identifier is an IPv4 range"""
        range_match=self.ip4_range_pattern.match(object_ident)
        if range_match is None:
             return False
        try:
            ip_address(range_match.group("start"))
            ip_address(range_match.group("end"))
            return True
        except ValueError:
            return False

    def is_ip6_range(self, object_ident):
        """Detect if the identifier is an IPv6 range"""
        range_match=self.ip6_range_pattern.match(object_ident)
        if range_match is None:
             return False
        try:
            ip_address(range_match.group("start"))
            ip_address(range_match.group("end"))
            return True
        except ValueError:
            return False

    def is_ip4(self, object_ident):
        """Detect if the identifier is an IPv4 address"""
        if self.ip4_pattern.match(object_ident) is None:
            return False
        try:
            ip_address(object_ident)
            return True
        except ValueError:
            return False
        
    def is_ip6(self, object_ident):
        """Detect if the identifier is an IPv6 address"""
        if self.ip6_pattern.match(object_ident) is None:
            return False
        try:
            ip_address(object_ident)
            return True
        except ValueError:
            return False
    
    def is_cidr(self, object_ident):
        """Detect if the identifier is a CIDR"""
        ip4_match = self.ip4_cidr_pattern.match(object_ident)
        #print(f"ip4_match {ip4_match}")
        if ip4_match and ip4_match.group("prefix"):
            try:
                ip_network(object_ident, strict=True)
                return True
            except ValueError:
                return False
        ip6_match = self.ip6_cidr_pattern.match(object_ident)
        if ip6_match and ip6_match.group("prefix"):
            try:
                ip_network(object_ident, strict=True)
                return True
            except ValueError:
                return False
        return False

    def is_mac(self, object_ident):
        """Detect if the identifier is a MAC address"""
        return self.mac_pattern.match(object_ident) is not None
    
    def is_fqdn(self, object_ident):
        """Detect if the identifier is a FQDN"""
        return self.fqdn_pattern.match(object_ident) is not None
    
    def is_id(self, object_ident):
        """Detect if the identifier is an ID (integer)"""
        return self.id_pattern.match(object_ident) is not None

    def match_type(self, object_ident, type=None):
        '''Detect the category of common identifiers like CIDR, range, IP, MAC, fqdn, id, other
        'category' is generally the 'collection' name in the BlueCat API,
        where CIDR and range could be a block or a network,
        and other could be a filename or other, or an error.
        No BlueCat lookups are done, this is just based on the format of the identifier.
        Returns type, value 
        where type is one of:
        id returns ("id", int)
        MAC returns ("MACAddress", string)
        IPv4 returns ("IP4Address", ipaddress)
        IPv6 returns ("IP6Address", ipaddress)
        CIDR returns ("CIDR", ipaddress-network), could be block or network
        range (IPv4 or IPv6) returns ("range", string), could be block or network
        fqdn returns ("fqdn", string), could be zone or RR
        other returns ("other", string), could be a filename or other type of identifier
        '''
        logging.debug(f"Matching type for {object_ident} with specified type {type}")
        error=None

        # The order is important, check more unique first
        if self.is_ip4_range(object_ident):
            obj_type="range"
            value=object_ident
        elif self.is_ip6_range(object_ident):
            obj_type="range"
            value=object_ident
        elif self.is_cidr(object_ident):
            obj_type="CIDR"
            value=object_ident
        elif self.is_ip4(object_ident):
            obj_type="IP4Address"
            value=object_ident
        elif self.is_ip6(object_ident):
            obj_type="IP6Address"  
            value=object_ident
        elif self.is_mac(object_ident):
            obj_type="MACAddress"
            value=object_ident
        elif self.is_fqdn(object_ident):
            obj_type="fqdn"
            value=object_ident
        elif self.is_id(object_ident):
            obj_type="id"
            value=int(object_ident)
        else:
            obj_type="other"
            value=object_ident
        
        logging.info(f"matched type: {obj_type}, value {value}, error {error}")
        return obj_type, value


    '''
    def detect_resource_type(self, identifier):
        """Detect whether the identifier is a zone, block, or network"""
        if self.is_fqdn(identifier):
             return "zone"
        if self.is_cidr(identifier):
            network_url = f"{self.mainurl}/networks?filter=range:eq('{identifier}')"
            response = requests.get(
                network_url, headers=self.auth_header, timeout=self.timeout
            )
            if response.status_code == 200 and response.json().get("data"):
                return "network"
            block_url = f"{self.mainurl}/blocks?filter=range:eq('{identifier}')"
            response = requests.get(
                block_url, headers=self.auth_header, timeout=self.timeout
            )
            if response.status_code == 200 and response.json().get("data"):
                return "block"
        return "unknown"
    '''

    def get_fqdn_or_cidr(self, identifier, links=True, type=None):
        """Detect whether the identifier is a zone, block, or network,
        returns the type and the list of objects, typically a list of one"""
        if links:
            header = self.auth_header_links
        else:
            header = self.auth_header_nolinks
        zone_pattern = r"[a-zA-Z0-9.-]+$"
        block_pattern = r"^\d+\.\d+\.\d+\.\d+/\d+$"  # Example: 192.168.0.0/24
        if re.match(zone_pattern, identifier):
            if type is None or type == "zone":
                fqdn_url = (
                    f"{self.mainurl}/zones?filter=absoluteName:eq('{identifier}')"
                )
                response = requests.get(fqdn_url, headers=header, timeout=self.timeout)
                if response.status_code == 200 and response.json().get("data"):
                    return "zone", response.json().get("data")
        if re.match(block_pattern, identifier):
            if type is None or type == "network":
                network_url = f"{self.mainurl}/networks?filter=range:eq('{identifier}')"
                response = requests.get(
                    network_url, headers=header, timeout=self.timeout
                )
                if response.status_code == 200 and response.json().get("data"):
                    return "network", response.json().get("data")
            if type is None or type == "block":
                block_url = f"{self.mainurl}/blocks?filter=range:eq('{identifier}')"
                response = requests.get(block_url, headers=header, timeout=self.timeout)
                if response.status_code == 200 and response.json().get("data"):
                    return "block", response.json().get("data")
        return "unknown", list()

    
    def get_obj_list(self, identifier, type=None):
        """Detect whether the identifier is a zone, block, or network, etc, or '-' or filename and
        returns the list of objects, typically a list of one"""
        if not type:    # if type is not specified, try to detect it
            type, value=self.match_type(identifier)
            logging.debug(f"match_type returned type {type} value {value}")
        header = self.auth_header_default
        logging.debug(f"{header}")
        if type in ("CIDR", "range", "network"):
             # CIDR or range could be a block or a network, so check Network first since it's more specific
            network_url = f"{self.mainurl}/networks?filter=range:eq('{identifier}')"
            response = requests.get(network_url, headers=header, timeout=self.timeout)
            if response.status_code == 200 and response.json().get("data"):
                return response.json().get("data")
            if type == 'network':
                return []  # if type is specified as network, don't check block
        if type in ("CIDR", "range", "block"):
            block_url = f"{self.mainurl}/blocks?filter=range:eq('{identifier}')"
            response = requests.get(block_url, headers=header, timeout=self.timeout)
            if response.status_code == 200 and response.json().get("data"):
                return response.json().get("data")
            else:
                return []
        if type in ("fqdn", "zone"):
            fqdn_url = (f"{self.mainurl}/zones?filter=absoluteName:eq('{identifier}')")
            response = requests.get(fqdn_url, headers=header, timeout=self.timeout)
            if response.status_code == 200 and response.json().get("data"):
                return response.json().get("data")
            if type == 'zone':
                return []  # if type is specified as zone, don't check RR
        if type in ( "fqdn", "rr"):
            rr_url = f"{self.mainurl}/resourceRecords?filter=absoluteName:eq('{identifier}')"
            response = requests.get(rr_url, headers=header, timeout=self.timeout)
            if response.status_code == 200 and response.json().get("data"):
                return response.json().get("data")
        if type == "id":
            # get object by id
            obj_url = f"{self.mainurl}?filter=id:{value}"
            response = requests.get(obj_url, headers=header, timeout=self.timeout)
            if response.status_code == 200 and response.json().get("data"):
                return [response.json().get("data")]
        # *** other, etc
        return []
    
    def add_user(
        self,
        name,
        firstname,
        lastname,
        email,
        security_privilege,
        access_type,
        authenticator,
        history_privilege,
        groupname=None,
    ):
        """Add a user to BlueCat BAMv2 API"""
        print(f"Adding user {name} to BlueCat:", end=" ")
        # get authenticator
        url = f"{self.mainurl}/authenticators?filter=name:eq('{authenticator}')"
        response = self.get(url, headers=self.auth_header_nolinks, timeout=self.timeout)
        if response.status_code != 200:
            print(f"Failed to get authenticator ID. Error: {response.status_code}")
            logging.debug(response.text)
            return
        data = response.json()
        if not data["data"]:
            print(f"Authenticator {authenticator} not found.")
            return
        authenticator_id = data["data"][0]["id"]
        authenticator_type = data["data"][0]["type"]
        # add user
        url = f"{self.mainurl}/users"
        data = {
            "name": name,
            "userDefinedFields": {"firstname": firstname, "lastname": lastname},
            "email": email,
            "securityPrivilege": security_privilege,
            "accessType": access_type,
            "authenticator": {
                "id": authenticator_id,
                "type": authenticator_type,
                "name": authenticator,
            },
            "historyPrivilege": history_privilege,
        }
        response = self.post(
            url, headers=self.auth_header_default, json=data, timeout=self.timeout
        )
        if response.status_code == 201:
            print("Succeeded!")
        else:
            print(f"Failed {response.status_code}")
            print(response.text)
            return
        if groupname:
            self.add_user_to_group(response.json()["id"], groupname)

    def add_group(self, groupname, email=None):
        """Add a group"""
        # check if group exists?
        url=f"{self.mainurl}/groups?filter=name:eq('{urllib.parse.quote(groupname)}')"
        data={
            "name": groupname
        }
        if email:
            data["userDefinedFields"] =  {
                "email": email
            }
        response = self.post(
            url, headers=self.auth_header_default, json=data, timeout=self.timeout
        )
        if response.status_code == 201:
            print("Succeeded!")
        else:
            print(f"Failed {response.status_code}")
            print(response.text)
            return

    def add_user_to_group(self, userid, groupname):
        """Add a user to a group in BlueCat BAMv2 API"""
        print(f"Adding user to group {groupname}", end=" ")
        url = f"{self.mainurl}/groups?filter=name:eq('{urllib.parse.quote(groupname)}')"
        response = requests.get(url, headers=self.auth_header_nolinks, timeout=self.timeout)
        if response.status_code != 200:
            print("Failed to get group ID. Error:", response.text)
        data = response.json()
        if not data["data"]:
            print(f"Group {groupname} not found.")

        group_id = data["data"][0]["id"]

        url = f"{self.mainurl}/groups/{group_id}/users"
        msg = {"id": userid, "type": "User"}
        response = requests.post(
            url, headers=self.auth_header_default, json=msg, timeout=self.timeout
        )
        if response.status_code == 201:
            print("Succeeded!")
        else:
            print(f"Failed: {response.status_code}")
            print(response.text)

    def get_user_groups(self, username):
        """Get user groups by username"""
        print(f"Getting user {username} groups", end=" ")

        url = f"{self.mainurl}/users?filter=name:eq('{username}')"
        response = requests.get(url, headers=self.auth_header_nolinks, timeout=self.timeout)
        if response.status_code != 200:
            print("Failed to get user ID. Error:", response.text)
        data = response.json()
        if not data["data"]:
            print(f"User {username} not found.")

        user_id = data["data"][0]["id"]

        url = f"{self.mainurl}/users/{user_id}/groups"
        response = requests.get(url, headers=self.auth_header_default, timeout=self.timeout)
        if response.status_code != 200:
            print(f"Failed: {response.status_code}")
            logging.debug(response.text)
            return None
        data = response.json()
        if not data["data"]:
            print("Not found.")
            return None
        print("Success.")
        for group in data["data"]:
            print(group["id"], group["name"])
        return data["data"]

    def get_group_users(self, groupname):
        """Get users by groupname"""
        print(f"Getting group {groupname} users", end=" ")

        url = f"{self.mainurl}/groups?filter=name:eq('{urllib.parse.quote(groupname)}')"
        response = requests.get(url, headers=self.auth_header_nolinks, timeout=self.timeout)
        if response.status_code != 200:
            print("Failed to get group ID. Error:", response.text)
        data = response.json()
        if not data["data"]:
            print(f"Group {groupname} not found.")

        group_id = data["data"][0]["id"]

        url = f"{self.mainurl}/groups/{group_id}/users"
        response = requests.get(url, headers=self.auth_header_default, timeout=self.timeout)
        if response.status_code != 200:
            print(f"Failed: {response.status_code}")
            logging.debug(response.text)
            return None
        data = response.json()
        if not data["data"]:
            print("Not found.")
            return None
        print("Success.\n")
        for user in data["data"]:
            print(
                user["id"],
                user["name"],
                user["userDefinedFields"]["firstname"],
                user["userDefinedFields"]["lastname"],
                user["email"],
                f"\"{user['userDefinedFields']['department']}\" {user['accessType']}",
                f"{'Active' if not user['accountLocked'] else 'Locked'}",
                f"\"{user['authenticator']['name']}\"",
                "Admin" if user["securityPrivilege"] == "ADMINISTRATOR" else "Normal",
            )
        return data["data"]

    def get_user(self, username, groupflag=False):
        """Get user info by username"""
        # print(f"Getting user {username}", end=" ")
        if groupflag:
            url = f"{self.mainurl}/users?filter=name:eq('{username}')&fields=embed(groups)"
        else:
            url = f"{self.mainurl}/users?filter=name:eq('{username}')"
        response = requests.get(url, headers=self.auth_header_default, timeout=self.timeout)
        if response.status_code != 200:
            print(f"Failed: {response.status_code}")
            logging.debug(response.text)
            return None
        data = response.json()
        if not data["data"]:
            print("Not found.")
            return None
        # print("Success.")
        # user = data["data"][0]

        # print(
        #     user["id"],
        #     user["name"],
        #     user["userDefinedFields"]["firstname"],
        #     user["userDefinedFields"]["lastname"],
        #     user["email"],
        #     f"\"{user['userDefinedFields']['department']}\" {user['accessType']}",
        #     f"{'Active' if not user['accountLocked'] else 'Locked'}",
        #     f"\"{user['authenticator']['name']}\"",
        #     "Admin" if user["securityPrivilege"] == "ADMINISTRATOR" else "Normal",
        # )
        return data["data"][0]

    def get_rr(self, hostname):
        """Get Resource Records by hostname and configuration, return a list"""
        url1 = f"{self.mainurl}/resourceRecords"
        url2 = f"?filter=absoluteName:eq('{hostname}')"
        logging.debug(f"config name {self.configuration_name}")
        if self.configuration_name:
            url2a = f"and configuration.name:eq('{self.configuration_name}')"
        else:
            url2a=""
        # just the basic fields?
        url3 = f"&fields=id,type,name,configuration.id,configuration.name,ttl"
        url4 = f",absoluteName,linkedRecord.id,linkedRecord.type,linkedRecord.absoluteName"
        url = "".join([url1,url2,url2a,url3,url4])
        # or all the fields?
        url = "".join([url1,url2,url2a])
        logging.debug(url)
        response = requests.get(url, headers=self.auth_header_default, timeout=self.timeout)
        if response.status_code != 200:
            print(f"Failed: {response.status_code}")
            logging.debug(response.text)
            return None
        data = response.json()
        if not data["data"]:
            print("Not found.")
            return None
        return data["data"]

    def update_alias_cname(self, alias, hostname, ttl=None):
        """Update Alias (CNAME) record"""
        # get existing alias and check
        data = self.get_rr(alias)
        # if data['count'] != 1:
        #    logging.info("Looking for 1 alias(CNAME), but got ",data.__str__)
        #    raise ValueError
        #    return None
        # rr=data['data'][0]
        # print(f"get_rr returned {data.__str__()}")
        rr = data[0]  # should only be one alias record
        if rr["type"] != "AliasRecord":
            logging.error("Looking for AliasRecord but found %s", rr["type"])
            return None
        if rr["linkedRecord"]["absoluteName"] == hostname and rr["ttl"] == ttl:
            logging.error("no change needed")
            return rr["id"]
        # get new linked hostname
        linked = self.get_rr(hostname)
        if linked is None:
            logging.error("failed to find %s", hostname)
            return None
        if len(linked) > 1:
            print("Error, more than one choice for linked hostname object")
            return None
        linkid = linked[0]["id"]

        # now update alias
        rr["linkedRecord"]["absoluteName"] = hostname
        rr["ttl"] = ttl
        rr["linkedRecord"]["id"] = linkid
        url = f"{self.mainurl}/resourceRecords/{rr['id']}"
        response = requests.put(
            url, headers=self.auth_header_default, json=rr, timeout=self.timeout
        )
        if response.status_code in (200, 201):
            newrr = response.json()
            # print(newrr)
            print(
                f"Updated alias(CNAME) {newrr['absoluteName']} CNAME {newrr['linkedRecord']['absoluteName']}"
            )
        else:
            print(f"Failed: {response.status_code}")
            print(response.text)
        return rr["id"]

    def get_resource_records(self, **kwargs):
        """typical arguments are filter, fields, limit, ..."""
        url = f"{self.mainurl}/resourceRecords"
        delim = "?"
        for n, v in kwargs.items():
            url += f"{delim}{n}={v}"
            delim = "&"
        response = requests.get(url, headers=self.auth_header_default, timeout=self.timeout)
        if response.status_code != 200:
            print(f"Failed: {response.status_code}")
            logging.debug(response.text)
            return None
        data = response.json()
        return data

    def selectivedeployment(self, resources):
        """selective deployment"""
        msg = {"type": "SelectiveDeployment", "resources": []}
        if isinstance(resources, list):
            msg["resources"] = resources
        else:
            msg["resources"] = [resources]
        # where resources is a list of {"id": 1234, "type": "HostRecord"},
        url = f"{self.mainurl}/deployments"
        response = requests.post(
            url, headers=self.auth_header_default, json=msg, timeout=self.timeout
        )
        # print(response.json())
        data = response.json()
        return data

    def getdeployment(self, deployment_id, wait="nowait"):
        """get status of a deployment, and optionally wait ('quiet' or 'verbose') for completetion"""
        url = f"{self.mainurl}/deployments/{deployment_id}"
        status = ""
        state = ""
        while True:
            response = requests.get(url, headers=self.auth_header_default, timeout=self.timeout)
            # print(response.json())
            data = response.json()
            if wait == "nowait":
                break
            if wait == "verbose":
                if data["status"] != status:
                    status = data["status"]
                    print(f"{datetime.now():%H:%M:%S} .. status: {status} .. ")
                if data["state"] != state:
                    state = data["state"]
                    print(f"{datetime.now():%H:%M:%S}  .. state: {state} .. ")
            if data["state"] not in ["PENDING", "QUEUED", "RUNNING"]:
                break
            time.sleep(1)
        return data

    def get_mac_pool(self, poolname):
        """Get MAC Pool by name, return mac pool object, error message"""
        # poolobj,errmsg = get_mac_pool(poolname)
        fqdn_url = (
            f"{self.mainurl}/macPools?filter=name:eq('{poolname}')&fields=id,type,name"
        )
        response = requests.get(
            fqdn_url, headers=self.auth_header_nolinks, timeout=self.timeout
        )
        poolobjs = response.json().get("data")
        if response.status_code == 200 and poolobjs:
            if len(poolobjs) > 1:
                return None, "more than one pool with same name"
            return poolobjs[0], None
        return None, "no pool found"

    @staticmethod
    def format_mac_address(mac):
        """format MAC Address in BlueCat/Windows format (dashes)"""
        dots = re.search(
            r"(?P<hex1>[0-9a-fA-F]{2})(?P<hex2>[0-9a-fA-F]{2})[.](?P<hex3>[0-9a-fA-F]{2})(?P<hex4>[0-9a-fA-F]{2})[.](?P<hex5>[0-9a-fA-F]{2})(?P<hex6>[0-9a-fA-F]{2})",
            mac
        )
        if dots:
            newmac = f"{dots.group("hex1")}-{dots.group("hex2")}-{dots.group("hex3")}-{dots.group("hex4")}-{dots.group("hex5")}-{dots.group("hex6")}"
            newmac=newmac.upper()
            return newmac
        colons = re.search(
            r"(?P<hex1>[0-9a-fA-F]{1:2})\.(?P<hex2>[0-9a-fA-F]{1:2})\.(?P<hex3>[0-9a-fA-F]{1:2})\.(?P<hex4>[0-9a-fA-F]{1:2})\.(?P<hex5>[0-9a-fA-F]{1:2})\.(?P<hex6>[0-9a-fA-F]{1:2})",
            mac
        )
        if colons:
            newmaclist=[]
            for i in range(6):
                a=colons.group(i)
                if len(a) ==1:
                    a = "0" + a
                newmaclist.append(a)
            newmac=".".join(newmaclist)
            newmac=newmac.upper()
            return newmac
        dashes = re.search(
            r"(?P<hex1>[0-9a-fA-F]{2})-(?P<hex2>[0-9a-fA-F]{2})-(?P<hex3>[0-9a-fA-F]{2})-(?P<hex4>[0-9a-fA-F]{2})-(?P<hex5>[0-9a-fA-F]{2})-(?P<hex6>[0-9a-fA-F]{2})",
            mac
        )
        if dashes:
            newmac=mac
            newmac=newmac.upper()
            return newmac
        print(f"ERROR - Mac Address '{mac}' not recognized")
        return mac

    def find_zone(self, fqdn):
        """find zone name from fqdn, return zone obj, remainder, error msg"""
        # hostname could be dotted
        errormsg = None
        domain_label_list = fqdn.split(".")
        zone_end = len(domain_label_list)
        zone_start = 0
        search_domain = ".".join(domain_label_list[zone_start:])
        found_zone_obj = None

        while True:
            # print(f"look for zone {search_domain}")
            url = f"{self.mainurl}/zones?filter=absoluteName:eq('{search_domain}') and view.id:eq({self.view_id})"
            response = requests.get(url, headers=self.auth_header_default, timeout=self.timeout)
            if response.status_code == 404:  # try next level, this is expected
                zone_start += 1  # increment by one
                search_domain = ".".join(domain_label_list[zone_start:zone_end])
                continue

            if response.status_code != 200:  # unexpected error
                errormsg = response.json()
                return None, None, errormsg

            data = response.json()
            if data["count"] > 1:
                errormsg = "matched more than one zone"
                return None, None, errormsg

            if data["count"] == 0 and zone_start < zone_end:  # try next level
                zone_start += 1  # decrement by one
                search_domain = ".".join(domain_label_list[zone_start:zone_end])
                continue

            if data["count"] == 0 and zone_start >= zone_end:
                errormsg = "zone not found"
                return None, None, errormsg  # ran out of levels

            if data["count"] == 1:
                # found the zone
                found_zone_obj = data["data"][0]
                remainder = ".".join(domain_label_list[:zone_start])
                return found_zone_obj, remainder, errormsg

        remainder = ".".join(domain_label_list[0:zone_end])
        return found_zone_obj, remainder, errormsg

    def get_ip(self, ip):
        """get IP4 or IP6 object, return obj,errormsg"""
        url = f"{self.mainurl}/addresses?filter=address:eq('{ip}') and configuration.name:eq('{self.configuration_name}')"
        response = requests.get(url, headers=self.auth_header_default, timeout=self.timeout)
        if response.status_code != 200:  # unexpected error
            errormsg = response.json()
            return None, errormsg
        #print(f"{response.json()}")
        return response.json(), None


    def get_block(self,ip, links=True):
        """get closest enclosing block for IP Address, including blocks defined by a range, return blockobj,errormsg"""
        url = f"{self.mainurl}/blocks?filter=configuration.name:eq('{self.configuration_name}') and range:contains('{ip}')"
        # Need the links on this one
        response = self.get(
            url, links=True, timeout=self.timeout
        )
        if not response.status_code == 200:
            logging.debug(response.text)
            return None,response.text
        data = response.json()
        logging.debug(data)
        if not data["data"]:
            return None,"no blocks found"
        
        # find the closest block in the list
        blocklist = data["data"]
        parentlist=list()
        for block in blocklist:
            fields = block['_links']['up']['href'].split('/')
            parentlist.append(int(fields[4]))
        toplist=list()
        for block in blocklist:
            if block['id'] not in parentlist:
                toplist.append(block)
        if len(toplist)==1:
            block = toplist[0]
            if not links:
                block = self.removelinks(block)
            return block,None   # the closet enclosing block, not a parent of another enclosing block
        else:
            return None,f"Error: more than one closest enclosing block? {toplist}"

    def get_network(self,ip, links=True):
        '''Get network that includes the given IP, return obj,errormsg'''
        # if CIDR, do exact match
        if '/' in ip:
            networklist=self.get_obj_list(ip, type="network")
            if len(networklist) == 0:
                return None, f"Network not found for: {ip}"
            if len(networklist) > 1:
                return None, f"ERROR: Multiple networks found for {ip}"
            return networklist[0],None
       # else, do range:contains
        url=f"{self.mainurl}/networks?filter=configuration.name:eq('{self.configuration_name}') and range:contains('{ip}')"
        response=self.get(
            url, links=True
        )
        logging.debug(f"got {response}")
        if response.status_code != 200:
            return None, response.text
        resp=response.json()
        logging.debug(f"get_network.py got {resp}")

        if not resp.get("data"):
            return None, f"Network not found for: {ip}"
        if resp['count'] == 0:
            return None, f"Network not found for: {ip}"
        if resp['count'] > 1:
            return None, f"ERROR: Multiple networks found for {ip}"
        network = resp["data"][0]
        if not links:
            network = self.removelinks(network)
        return network, None

