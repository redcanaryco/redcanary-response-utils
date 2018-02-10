#!/usr/bin/env python

"""
OVERVIEW

Extract network connection data from Cb Response based on one or more
criteria:

- Time (past N minutes, days)
- CbER query match
- CbER query whitelist
- IP whitelist w/ one or more of: specific addresses, loopback, multicast.
- Host type: workstation or server

Results are written to a file named . . . wait for it . . . results.csv.

USE CASES AND EXAMPLES

--> Show network connections within the past hour

./netconn-util.py --minutes 60

--> Show the above, but do not inspect any web browser processes

./netconn-util.py --minutes 60 --whitelist whitelist.browsers

--> Show network connections associated with a given user

./netconn-util.py --minutes 60 --query 'username:joeuser'

--> Show network connections from some system processes:

./netconn-util.py --minutes 60 --query 'process_name:explorer.exe or
process_name:svchost.exe'

--> Show inbound network connections

./netconn-util.py --minutes 60 --inbound

--> Show inbound network connections to workstations

./netconn-util.py --minutes 60 --inbound --workstations

WHITELISTS

Whitelists are text files with one query term per line, all of which will be
added to the query that is eventually executed. Thus, you must be mindful of
whitelist size so as not to exceed the maximum length of a CbER query.

Whitelists are used as much for performance as they are for accuracy. That
meaning, you can and should use them to avoid iterating over thousands of
network connections for process that do not matter to your inquiry.

As an example, the contents of whitelist.browsers above may look like:

-process_name:firefox.exe
-process_name:firefox
-process_name:chrome.exe
-process_name:chrome
-process_name:iexplore.exe

CREDITS

- Many early improvements from TS.
"""

import argparse
import csv
import ipaddress
import os
import re
import sys
from datetime import datetime

from common import *

from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import Process, Sensor


if sys.version_info.major >= 3:
    _python3 = True
else:
    _python3 = False


def build_whitelist(filename):
    f = open(filename, 'rb')
    terms = f.readlines()
    f.close()

    whitelist = ''
    for term in terms:
        whitelist += ' {0}'.format(term.strip())

    return whitelist


def get_hosts(filename):
    f = open(filename, 'rb')
    hosts = f.readlines()
    f.close()

    filtered_hosts = set()
    for host in hosts:
        host = host.strip()

        # Filter out invalid IPs
        if not re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', host):
            continue

        filtered_hosts.add(host)

    return filtered_hosts


def convert_timestamp(datetime_obj):
    return datetime_obj.strftime('%Y%m%d-%H%M%S')


def process_search(cb_conn, query, query_base=None, limit=None,
                   direction=None, loopback=None, ignore_hosts=None,
                   ignore_private_dest=False,
                   multicast=None, tcp=True, udp=True,
                   domain=None):

    re_multicast = re.compile(r'2(?:2[4-9]|3\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d?|0)){3}')

    if query_base != None:
        query += query_base

    log_info("QUERY: {0}".format(query))
    query_result = cb_conn.select(Process).where(query).group_by("id")
    query_result_len = len(query_result)
    log_info("RESULT COUNT: {0}".format(query_result_len))

    results = set()

    try:
        process_counter = 0
        for proc in query_result:
            process_counter += 1
            if process_counter % 100 == 0:
                log_info('Processing {0} of {1} results'.format(process_counter, query_result_len))

            if proc.netconn_count == 0:
                continue

            path = proc.path
            hostname = proc.hostname.lower()
            username = proc.username.lower()

            inspect_counter = 0
            for netconn in proc.netconns:
                inspect_counter += 1
                if inspect_counter > limit:
                    log_info("Reached inspect-limit ({0})".format(limit))
                    break

                src_ip = ipaddress.ip_address(netconn.local_ip)
                dst_ip = ipaddress.ip_address(netconn.remote_ip)

                if direction is not None and direction != netconn.direction:
                    continue
                elif ignore_private_dest == True and dst_ip.is_private == True:
                    continue
                elif tcp == False and netconn.proto == 'IPPROTO_TCP':
                    continue
                elif udp == False and netconn.proto == 'IPPROTO_UDP':
                    continue
                elif loopback == False and (src_ip.is_loopback == True or \
                                            dst_ip.is_loopback == True):
                    continue
                elif ignore_hosts and netconn.remote_ip in ignore_hosts:
                    continue
                elif multicast == False and src_ip.is_multicast == True:
                    continue
                elif domain is not None and domain not in netconn.domain:
                    continue

                results.add((convert_timestamp(netconn.timestamp),
                            path,
                            hostname,
                            username,
                            netconn.domain,
                            netconn.proto,
                            netconn.direction,
                            netconn.local_ip,
                            netconn.local_port,
                            netconn.remote_ip,
                            netconn.remote_port,
                            proc.webui_link
                            ))
    except KeyboardInterrupt:
        print("Caught CTRL-C. Returning what we have . . .")

    return results


def main():
    parser = build_cli_parser("Network utility")

    # Non-exlusive query terms. Note that we're passing them this way because
    # we can't risk the user passing terms that Cb can't search (i.e., a
    # process-level term plus an event-level term). These are joined by AND, 
    # not OR.
    parser.add_argument("--hostname", type=str, action="store",
                        help="Search for hostname")
    parser.add_argument("--username", type=str, action="store",
                        help="Search for username")

    # Whitelist conditions
    parser.add_argument("--whitelist", type=str, action="store",
                        help="Path to whitelist file.")
    parser.add_argument("--ignore-hosts", type=str, action="store",
                        help="Path to file listing IPs to ignore traffic to/from.")
    parser.add_argument("--noloopback", action="store_false",
                        help="Ignore connections to and from 127.0.0.1.")
    parser.add_argument("--nomulticast", action="store_false",
                        help="Ignore multicast connections")
    parser.add_argument("--ignore-private-dest", action="store_true",
                        help="Ignore connections to RFC1918 networks.")

    # Traffic attributes
    d = parser.add_mutually_exclusive_group(required=False)
    d.add_argument("--inbound", action="store_true",
                   help="Report only inbound netconns.")
    d.add_argument('--outbound', action="store_true",
                   help="Report only outbound netconns.")

    p = parser.add_mutually_exclusive_group(required=False)
    p.add_argument("--tcp", action="store_true",
                   help="Report only UDP netconns.")
    p.add_argument('--udp', action="store_true",
                   help="Report only TCP netconns.")

    # Endpoint attributes
    t = parser.add_mutually_exclusive_group(required=False)
    t.add_argument("--workstations", action="store_true",
                        help="Only process workstations.")
    t.add_argument("--servers", action="store_true",
                        help="Only process servers.")

    # Query and inspection limiting
    parser.add_argument("--inspect-limit", dest="inspect_limit", type=int,
                        action="store", default="5000",
                        help="Limit netconns per process that we inspect (default: 5000.")
    parser.add_argument("--min-netconn-count", type=int, action="store",
                        default="1", 
                        help="Minimum network connections associated with process.")
    parser.add_argument("--max-netconn-count", type=int, action="store",
                        default="5000", 
                        help="Minimum network connections associated with process.")

    # Shortcuts for speed
    parser.add_argument("--domain", dest="domain", action="store",
                        help="Quick search for only those events with a domain match.")
    parser.add_argument("--port", dest="port", action="store",
                        help="Quick search for only those events involving a specific port.")
    parser.add_argument("--ipaddr", dest="ipaddr", action="store",
                        help="Quick search for only those events with an IP match.")

    args = parser.parse_args()

    if args.prefix:
        output_filename = '%s-netconns.csv' % args.prefix
    else:
        output_filename = 'netconns.csv'

    if args.append == True or args.queryfile is not None:
        file_mode = 'a'
    else:
        file_mode = 'w'

    # Query buildup
    if args.days:
        query_base = ' start:-%dm' % (args.days*1440)
    elif args.minutes:
        query_base = ' start:-%dm' % args.minutes
    else:
        query_base = ''

    if args.servers:
        query_base += ' (host_type:"domain_controller" OR host_type:"server")'
    elif args.workstations:
        query_base += ' host_type:"workstation"'

    if args.hostname:
        query_base += ' hostname:{0}'.format(args.hostname)
    if args.username:
        query_base += ' username:{0}'.format(args.username)

    if args.whitelist:
        query_base += build_whitelist(args.whitelist)

    if args.ignore_hosts:
        ignore_hosts = get_hosts(args.ignore_hosts)

    if args.domain:
        query_base += ' domain:%s' % args.domain
    elif args.ipaddr:
        query_base += ' ipaddr:%s' % args.ipaddr
    elif args.port:
        query_base += ' ipport:%s' % args.port
    else:
        query_base += ' netconn_count:[{0} to {1}]'.format(args.min_netconn_count,
                                                           args.max_netconn_count)

    if args.inbound:
        direction = 'Inbound'
    elif args.outbound:
        direction = 'Outbound'
    else:
        direction = None

    udp = True
    tcp = True
    if args.tcp and not args.udp:
        udp = False
    elif args.udp and not args.tcp:
        tcp = False

    # Connect and stage queries 
    if args.profile:
        cb = CbEnterpriseResponseAPI(profile=args.profile)
    else:
        cb = CbEnterpriseResponseAPI()

    # TODO - Update this routine to guard against impossible queries.
    queries = []
    if args.query:
        queries.append(args.query)
    elif args.queryfile:
        with open(args.queryfile, 'r') as f:
            for query in f.readlines():
                if ':' in query:
                    queries.append(query.strip())
        f.close()
    else:
        queries.append('')

    # Main routine and output
    output_file = open(output_filename, file_mode)
    writer = csv.writer(output_file)
    if args.append is False:
        writer.writerow(["timestamp",
                        "path",
                        "hostname",
                        "username",
                        "domain",
                        "proto",
                        "direction",
                        "local_ip",
                        "local_port",
                        "remote_ip",
                        "remote_port"])

    for query in queries:
        result_set = process_search(cb, query, query_base,
            limit=args.inspect_limit,
            direction=direction,
            loopback=args.noloopback,
            ignore_hosts=args.ignore_hosts,
            ignore_private_dest=args.ignore_private_dest,
            multicast=args.nomulticast,
            tcp=tcp, udp=udp,
            domain=args.domain)

        for r in result_set:
            row = list(r)
            if _python3 == False:
                row = [col.encode('utf8') if isinstance(col, unicode) else col for col in row]
            writer.writerow(row)

    output_file.close()


if __name__ == '__main__':

    sys.exit(main())
