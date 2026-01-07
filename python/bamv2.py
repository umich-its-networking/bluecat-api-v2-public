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
        server,
        username,
        password,
        timeout=None,
        max_retries=None,
        configuration_name=None,
        view_name=None
    ):
        """login to BlueCat server API, get token, set header"""
        self.username = username
        self.password = password
        self.timeout = timeout
        self.configuration_id = None
        self.configuration_name = configuration_name
        self.view_id = None
        self.view_name = view_name
        # self.parentviewcache = {}  # zoneid: viewid
        if not (server and username and password):
            print("server, username, and password are required.\n")
            raise requests.RequestException
        self.server = server
        self.mainurl = f"https://{server}/api/v2"
        logging.info("url: %s", self.mainurl)

        requests.Session.__init__(self)
        if max_retries:
            adapter = requests.adapters.HTTPAdapter(max_retries=max_retries)
            url_prefix = self.mainurl.split("://", 1)[0] + "://"
            self.mount(url_prefix, adapter)
        self.login()
        # set up compiled patterns once at start for later .match
        self.ip_pattern = re.compile(
            r"^(?P<start>(?:\d{1,3}\.){3}\d{1,3})"
            r"(?:\/(?P<prefix>\d{1,2})|"
            r"-(?P<end>(?:\d{1,3}\.){3}\d{1,3})|)$"
        )
        self.id_pattern = re.compile(r"\d+$")
        self.mac_pattern = re.compile(
            r"^((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}|"
            "[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{4}[.]){2}[0-9a-fA-F]{4})"
        )   
        self.fqdn_pattern = re.compile(r"[a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)*")


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

        self.auth_header = {
            "accept": "application/hal+json",
            "Authorization": f"Basic {self.basic_auth_credentials}",
            "Content-Type": "application/hal+json",
        }

        # included in JSON representations
        # when the media type application/hal+json or */* is set in the Accept header of the HTTP request.
        # A media type of application/json will exclude the _links field in resource representations.
        self.auth_header_nolinks = {
            "accept": "application/json",
            "Authorization": f"Basic {self.basic_auth_credentials}",
            "Content-Type": "application/hal+json",
        }

    def logout(self):
        """log out of BlueCat server, return nothing"""
        msg = {"state": "LOGGED_OUT"}
        logout_url = self.mainurl + "/sessions/current"
        header = self.auth_header
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
            "--configuration",
            "--cfg",
            help="BlueCat Configuration name",
            default=os.getenv("BLUECAT_CONFIGURATION"),
        )
        config.add_argument(
            "--view", help="BlueCat View", default=os.getenv("BLUECAT_VIEW")
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

    def get_config_and_view(self, configuration_name, view_name=None):
        """get configuration_id and view_id"""
        # usage: (configuration_id, view_id) =
        #    conn.get_config_and_view(configuration_name, view_name)
        # or for just configuration:
        # (configuration_id, _) = conn.get_config_and_view(configuration_name)

        configuration_url = f"{self.mainurl}/configurations?fields=id,name&filter=name:eq('{configuration_name}')"
        response = requests.get(
            configuration_url, headers=self.auth_header, timeout=self.timeout
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
                view_url, headers=self.auth_header, timeout=self.timeout
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

        if resource_type is None:
            resource_type = self.detect_resource_type(identifier)

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

        response = requests.get(url, headers=self.auth_header, timeout=self.timeout)

        if response.status_code != 200:
            print(f"Failed: {response.status_code} Error")
            logging.debug(response.text)

        data = response.json()
        if not data["data"]:
            print("Not found.")
            return None
        resource_id = data["data"][0]["id"]
        resource_type = resource_type + "s"

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

        response = requests.get(url, headers=self.auth_header, timeout=self.timeout)
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

    def match_type(self, object_ident, type=None, file=None):
        '''Detect common identifiers like CIDR, range, IP, MAC, fqdn, id, other
        where CIDR could be block or network,
        and other could be a filename or other, or an error,
        Returns type, value, error
        id returns ("id", None, None)
        MAC returns ("MACAddress", None, None)
        IP returns ("IP4Address", ip, None)
        CIDR returns ("CIDR", start, prefix)
        range returns ("range", start, end)
        fqdn returns ("fqdn", None, None)
        other returns ("other", None, None)
        '''
        logger = logging.getLogger()
        part1=""
        part2=""
        id_match = self.id_pattern.match(object_ident)
        if id_match:
            obj_type = "id"
        else:
            mac_match = self.mac_pattern.match(object_ident)
            if mac_match:
                obj_type = "MACAddress"
            else:
                ip_match = self.ip_pattern.match(object_ident)
                if ip_match and ip_match.group("start"):
                    part1 = ip_match.group("start")
                    if ip_match.group("prefix"):
                        obj_type = "CIDR"  # IP4Block or IP4Network
                        part2 = ip_match.group("prefix")
                    elif ip_match.group("end"):
                        obj_type = "DHCP4Range"
                        part2 = ip_match.group("end")
                    else:
                        obj_type = "IP4Address"
                else:
                    fqdn_match = self.fqdn_pattern.match(object_ident)
                    if fqdn_match:
                        obj_type = "fqdn"
                    else:
                        obj_type = None
        logger.info("matched type: %s, part1 %s, part2 %s", obj_type, part1, part2)
        return obj_type, part1, part2



    def detect_resource_type(self, identifier):
        """Detect whether the identifier is a zone, block, or network"""
        zone_pattern = r"[a-zA-Z0-9.-]+$"
        block_pattern = r"^\d+\.\d+\.\d+\.\d+/\d+$"  # Example: 192.168.0.0/24
        if re.match(zone_pattern, identifier):
            return "zone"
        if re.match(block_pattern, identifier):
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

    def get_fqdn_or_cidr(self, identifier, links=True, input_type=None):
        """Detect whether the identifier is a zone, block, or network,
        returns the type and the list of objects, typically a list of one"""
        if links:
            header = self.auth_header
        else:
            header = self.auth_header_nolinks
        zone_pattern = r"[a-zA-Z0-9.-]+$"
        block_pattern = r"^\d+\.\d+\.\d+\.\d+/\d+$"  # Example: 192.168.0.0/24
        if re.match(zone_pattern, identifier):
            if input_type is None or input_type == "zone":
                fqdn_url = (
                    f"{self.mainurl}/zones?filter=absoluteName:eq('{identifier}')"
                )
                response = requests.get(fqdn_url, headers=header, timeout=self.timeout)
                if response.status_code == 200 and response.json().get("data"):
                    return "zone", response.json().get("data")
        if re.match(block_pattern, identifier):
            if input_type is None or input_type == "network":
                network_url = f"{self.mainurl}/networks?filter=range:eq('{identifier}')"
                response = requests.get(
                    network_url, headers=header, timeout=self.timeout
                )
                if response.status_code == 200 and response.json().get("data"):
                    return "network", response.json().get("data")
            if input_type is None or input_type == "block":
                block_url = f"{self.mainurl}/blocks?filter=range:eq('{identifier}')"
                response = requests.get(block_url, headers=header, timeout=self.timeout)
                if response.status_code == 200 and response.json().get("data"):
                    return "block", response.json().get("data")
        return "unknown", {}

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
        response = self.get(url, headers=self.auth_header, timeout=self.timeout)
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
            url, headers=self.auth_header, json=data, timeout=self.timeout
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
            url, headers=self.auth_header, json=data, timeout=self.timeout
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
        response = requests.get(url, headers=self.auth_header, timeout=self.timeout)
        if response.status_code != 200:
            print("Failed to get group ID. Error:", response.text)
        data = response.json()
        if not data["data"]:
            print(f"Group {groupname} not found.")

        group_id = data["data"][0]["id"]

        url = f"{self.mainurl}/groups/{group_id}/users"
        msg = {"id": userid, "type": "User"}
        response = requests.post(
            url, headers=self.auth_header, json=msg, timeout=self.timeout
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
        response = requests.get(url, headers=self.auth_header, timeout=self.timeout)
        if response.status_code != 200:
            print("Failed to get user ID. Error:", response.text)
        data = response.json()
        if not data["data"]:
            print(f"User {username} not found.")

        user_id = data["data"][0]["id"]

        url = f"{self.mainurl}/users/{user_id}/groups"
        response = requests.get(url, headers=self.auth_header, timeout=self.timeout)
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
        response = requests.get(url, headers=self.auth_header, timeout=self.timeout)
        if response.status_code != 200:
            print("Failed to get group ID. Error:", response.text)
        data = response.json()
        if not data["data"]:
            print(f"Group {groupname} not found.")

        group_id = data["data"][0]["id"]

        url = f"{self.mainurl}/groups/{group_id}/users"
        response = requests.get(url, headers=self.auth_header, timeout=self.timeout)
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
        response = requests.get(url, headers=self.auth_header, timeout=self.timeout)
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
        """Get Resource Records by hostname, return a list, just the basic fields, 
        works for HostRecord, Alias(CNAME), TXT"""
        url1 = f"{self.mainurl}/resourceRecords"
        url2 = f"?filter=absoluteName:eq('{hostname}')"
        if self.configuration_name:
            url2a = f"and configuration.name:eq('{self.configuration_name}')"
        else:
            url2a=""
        url3 = f"&fields=embed(addresses),id,type,recordType,name,configuration.id,configuration.name,ttl"
        url4 = f",absoluteName,linkedRecord.id,linkedRecord.type,linkedRecord.absoluteName"
        url5 = f",text,rdata,userDefinedFields,_embedded.addresses"
        url = "".join([url1,url2,url2a,url3,url4,url5])
        response = requests.get(url, headers=self.auth_header, timeout=self.timeout)
        if response.status_code != 200:
            print(f"Failed: {response.status_code}")
            logging.debug(response.text)
            return None
        data = response.json()
        if not data["data"]:
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
            url, headers=self.auth_header, json=rr, timeout=self.timeout
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
        response = requests.get(url, headers=self.auth_header, timeout=self.timeout)
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
            url, headers=self.auth_header, json=msg, timeout=self.timeout
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
            response = requests.get(url, headers=self.auth_header, timeout=self.timeout)
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
            response = requests.get(url, headers=self.auth_header, timeout=self.timeout)
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

    def get_ip(self, ipaddressobj):
        """get IP4 or IP6 object, return obj,errormsg"""
        url = f"{self.mainurl}/addresses?filter=address:eq('{ipaddressobj}') and configuration.id:eq({self.configuration_id})"
        response = requests.get(url, headers=self.auth_header, timeout=self.timeout)
        if response.status_code != 200:  # unexpected error
            errormsg = response.json()
            return None, errormsg
        print(f"{response.json()}")
        return response.json(), None


    def get_block(self,ip, links=True):
        """get closest enclosing block for IP Address, including blocks defined by a range, return blockobj,errormsg"""
        network_url = f"{self.mainurl}/blocks?filter=configuration.name:eq('{self.configuration_name}') and range:contains('{ip}')"
        response = self.get(
            network_url, headers=self.auth_header, timeout=self.timeout
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
