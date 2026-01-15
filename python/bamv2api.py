#!/usr/bin/env python
"""BlueCat Address Manager v2 REST CLI
using the API Python module
"""
import os
import sys
import logging
import json
from bamv2 import BAMv2

def helper(method, args):
    """Process the method, data, and args from the CLI"""

    if method not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
        print(f"Invalid method '{method}'")
        print(f"Type '{os.path.basename(sys.argv[0])} -h' for help")
        sys.exit(2)

    if method in ["POST", "PUT", "PATCH"] and not args.data:
        print(f"Method '{method}' requires data")
        print(f"Type '{os.path.basename(sys.argv[0])} -h' for help")
        sys.exit(2)

    data_body = {}
    if method in ["POST", "PUT", "PATCH"]:
        try:
            data_body = json.loads(args.data)
        except json.JSONDecodeError:
            print(f"ERROR in data '{args.data}'")
            print(f"Type '{os.path.basename(sys.argv[0])} -h' for help")
            sys.exit(2)

    params = {}  # create the params dictionary
    for pair in args.args:
        try:
            name, value = pair.split("=", 1)  # "1" means only split on first "="
            params[name] = value
        except ValueError:
            print(f"ERROR in argument '{pair}'")
            print(f"Type '{os.path.basename(sys.argv[0])} -h' for help")
            sys.exit(2)

    return data_body, params


def parse(description=""):
    """Set up common argparse arguments for BlueCat API"""
    config = BAMv2.argparsecommon(description)
    config.add_argument(
        "command", help="BlueCat REST API command, for example: groups/124/users"
    )
    config.add_argument(
        "--method",
        "-m",
        default="GET",
        help="HTTP method, GET/POST/PUT/DELETE/PATCH",
    )
    config.add_argument(
        "--data",
        help="Data body to send with POST/PUT/PATCH, in quotes",
    )
    config.add_argument(
        "--args", nargs="*", default=[], help="Additional arguments, name=value"
    )
    return config


def main():
    """CLI - Command Line Interface"""
    description = "BlueCat Address Manager v2 REST API python module and CLI"
    config = parse(description)
    args = config.parse_args()

    logger = logging.getLogger()
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s")
    logger.setLevel(args.logging)

    if not (args.server and args.username and args.password):
        print(
            "server, username, and password are required.\n",
            "Please put them in the environment.\n",
        )
        print(f"Type '{os.path.basename(sys.argv[0])} -h' for help")
        sys.exit(1)

    method = args.method.upper()

    data, params = helper(method, args)

    with BAMv2(args.server, args.username, args.password, args.timeout) as session:
        url = f"{session.mainurl}/{args.command}"
        if args.links:
            header = session.auth_header
        else:
            header = session.auth_header_nolinks
        if method == "GET":
            response = session.get(
                url,
                params=params,
                headers=header,
                timeout=session.timeout,
            )
        elif method == "POST":
            response = session.post(
                url,
                json=data,
                params=params,
                headers=header,
                timeout=session.timeout,
            )
        elif method == "PUT":
            response = session.put(
                url,
                json=data,
                params=params,
                headers=header,
                timeout=session.timeout,
            )
        elif method == "DELETE":
            response = session.delete(
                url,
                headers=header,
                timeout=session.timeout,
            )
        elif method == "PATCH":
            header2 = header.copy()
            header2["Content-Type"] = "application/merge-patch+json"
            response = session.patch(
                url,
                json=data,
                params=params,
                headers=header2,
                timeout=session.timeout,
            )
        if method in ["GET", "PUT", "PATCH"] and response.status_code != 200:
            print("Failed Error:", response.text)
            sys.exit(3)
        if method == "DELETE" and response.status_code != 204:
            print("Failed Error:", response.text)
            sys.exit(3)
        if method == "POST" and response.status_code != 201:
            print("Failed Error:", response.text)
            sys.exit(3)
        data = response.json()
        print(json.dumps(data, indent=4))


if __name__ == "__main__":
    main()
