#!/usr/bin/env python

import argparse
import csv
import os
import sys
from datetime import datetime

# Carbon Black
from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import Process, Sensor
from cbapi.errors import *


if sys.version_info.major >= 3:
    _python3 = True
else:
    _python3 = False


def log_err(msg):
    """Format msg as an ERROR and print to stderr.
    """
    msg = 'ERROR: {0}\n'.format(msg)
    sys.stderr.write(msg)


def log_info(msg):
    """Format msg and print to stdout.
    """
    msg = '{0}\n'.format(msg)
    sys.stdout.write(msg)


def convert_timestamp(datetime_obj):
    return datetime_obj.strftime('%Y%m%d-%H%M%S')


def process_search(cb_conn, query, query_base=None):
    if query_base != None:
        query += query_base

    query_result = cb_conn.select(Process).where(query)
    query_result_len = len(query_result)
    log_info('Total results: {0}'.format(query_result_len))

    results = []

    try:
        process_counter = 0
        for proc in query_result:
            process_counter += 1
            if process_counter % 100 == 0:
                log_info('Processing {0} of {1}'.format(process_counter, query_result_len))

            hostname = proc.hostname.lower()
            username = proc.username.lower()
            path = proc.path
            cmdline = proc.cmdline

            try:
                process_md5 = path.process_md5
            except:
                process_md5 = ''

            parent_name = proc.parent_name

            results.append(('proc',
                            convert_timestamp(proc.start),
                            hostname,
                            username,
                            path,
                            cmdline,
                            process_md5,
                            parent_name,
                            proc.childproc_count,
                            proc.webui_link
                            ))

            for netconn in proc.netconns:
                results.append(('netconn',
                                convert_timestamp(netconn.timestamp),
                                hostname,
                                username,
                                path,
                                cmdline,
                                process_md5,
                                parent_name,
                                proc.childproc_count,
                                proc.webui_link,
                                netconn.domain,
                                netconn.remote_ip,
                                netconn.remote_port,
                                netconn.local_ip,
                                netconn.local_port,
                                netconn.proto,
                                netconn.direction
                                ))

            for filemod in proc.filemods:
                results.append(('filemod',
                                convert_timestamp(filemod.timestamp),
                                hostname,
                                username,
                                path,
                                cmdline,
                                process_md5,
                                parent_name,
                                proc.childproc_count,
                                proc.webui_link,
                                '','','','','','','', # netconn
                                filemod.path,
                                filemod.type,
                                filemod.md5
                                ))

            for regmod in proc.regmods:
                results.append(('regmod',
                                convert_timestamp(regmod.timestamp),
                                hostname,
                                username,
                                path,
                                cmdline,
                                process_md5,
                                parent_name,
                                proc.childproc_count,
                                proc.webui_link,
                                '','','','','','','',   # netconn
                                '','','',               # filemod
                                regmod.path,
                                regmod.type
                                ))


    except KeyboardInterrupt:
        log_info("Caught CTRL-C. Returning what we have . . .")

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=str, action="store",
                        help="The credentials.response profile to use.")

    # File output
    parser.add_argument("--prefix", type=str, action="store",
                        help="Output filename prefix.")
    parser.add_argument("--append", action="store_true",
                        help="Append to output file.")

    # Time
    parser.add_argument("--days", type=int, action="store",
                        help="Number of days to search.")
    parser.add_argument("--minutes", type=int, action="store",
                        help="Number of days to search.")
    
    # Cb Response inputs
    a = parser.add_mutually_exclusive_group(required=False)
    a.add_argument("--queryfile", type=str, action="store",
                   help="File containing queries, one per line.")
    a.add_argument('--query', type=str, action="store",
                   help="A single Cb query to execute.")

    # Output options
    parser.add_argument("--only-filemods", action="store_true",
                        help="Only output file modification records.")

    args = parser.parse_args()

    if args.prefix:
        output_filename = '{0}-timeline.csv'.format(args.prefix)
    else:
        output_filename = 'timeline.csv'

    if args.append == True or args.queryfile is not None:
        file_mode = 'a'
    else:
        file_mode = 'w'

    if args.days:
        query_base = ' start:-{0}m'.format(args.days*1440)
    elif args.minutes:
        query_base = ' start:-{0}m'.format(args.minutes)
    else:
        query_base = ''

    output_all = False
    if args.only_filemods:
        (output_netconns, output_regmods, output_procstarts) = (False, False, False)
        output_filemods = True
        query_base += ' filemod_count:[1 to *]' 
    else:
        output_all = True

    if args.profile:
        cb = CbEnterpriseResponseAPI(profile=args.profile)
    else:
        cb = CbEnterpriseResponseAPI()

    queries = []
    if args.query:
        queries.append(args.query)
    elif args.queryfile:
        with open(args.queryfile, 'r') as f:
            for query in f.readlines():
                queries.append(query.strip())
        f.close()
    else:
        queries.append('')

    output_file = open(output_filename, file_mode)
    writer = csv.writer(output_file)
    writer.writerow(["event_type",
                     "timestamp",
                     "hostname",
                     "username",
                     "path",
                     "cmdline",
                     "process_md5",
                     "parent",
                     "childproc_count",
                     "url",
                     "netconn_domain",
                     "netconn_remote_ip",
                     "netconn_remote_port",
                     "netconn_local_ip",
                     "netconn_local_port",
                     "netconn_proto",
                     "netconn_direction",
                     "filemod_path",
                     "filemod_type",
                     "filemod_md5",
                     "regmod_path",
                     "regmod_type"
                     ])

    for query in queries:
        result_set = process_search(cb, query, query_base)

        for row in result_set:
            if output_all == False:
                event_type = row[0]
                if output_filemods == True and 'filemod' not in event_type:
                    continue

            if _python3 == False:
                row = [col.encode('utf8') if isinstance(col, unicode) else col for col in row]
            writer.writerow(row)

    output_file.close()


if __name__ == '__main__':

    sys.exit(main())
