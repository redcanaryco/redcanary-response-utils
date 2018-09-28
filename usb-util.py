#!/usr/bin/env python

"""
OVERVIEW

Extract USB mass storage device events from Cb Response.
"""

import argparse
import csv
import json
import os
import sys

from common import *

from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import Process


if sys.version_info.major >= 3:
    _python3 = True
else:
    _python3 = False


# Use these to find registry events of interest. Disk device class is probably
# what you want, but you may also choose to fool with the volume device class
# as well: '{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
match_guid = ['{53f56307-b6bf-11d0-94f2-00a0c91efb8b}']

search_terms = ["registry\\machine\\system\\currentcontrolset\\control\\deviceclasses\\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\\*",
                "registry\\machine\\currentcontrolset\\control\\deviceclasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\\*"]


class USBEvent:
    def __init__(self, path):
        self.path = path

        self.vendor = ''
        self.product = ''
        self.version = ''
        self.serial = ''
        #self.drive_letter = ''
        #self.volume_name = ''

        self.parse()

    def __repr__(self):
        for k,v in self.__dict__.iteritems():
            print('{0},{1}'.format(k, v))

    def parse(self):
        path = self.path.split('usbstor#disk&')[1]
        fields = path.split('&')
        self.vendor = fields[0].split('ven_')[1]
        self.product = fields[1].split('prod_')[1]

        if self.vendor == 'drobo':
            # Drobo doesn't provide a version
            drobo_fields = self.product.split('#')
            self.product = drobo_fields[0]
            self.serial = drobo_fields[1]
        else:
            self.version = fields[2].split('#')[0].split('rev_')[1]
            self.serial = fields[2].split('#')[1]


def usbstor_search(cb_conn, query, query_base=None, timestamps=False):
    if query_base is not None:
        query += query_base

    query_result = cb_conn.select(Process).where(query)
    query_result_len = len(query_result)

    results = set()

    for proc in query_result:
        for regmod in proc.regmods:
            #TODO: Convert time boundary (minutes) and check against the
            # regmod event time to speed things up
            for guid in match_guid:
                if guid in regmod.path and 'usbstor#disk&' in regmod.path:
                    usb_result = USBEvent(regmod.path)

                    output_fields = [proc.hostname,
                                    usb_result.vendor,
                                    usb_result.product,
                                    usb_result.version,
                                    usb_result.serial]
                    if timestamps == True:
                        output_fields.insert(0, convert_timestamp(regmod.timestamp))

                    results.add(tuple(output_fields))

    return results


def main():
    parser = build_cli_parser("USB utility")

    # Output options
    parser.add_argument("--timestamps", action="store_true",
                        help="Include timestamps in results.")

    args = parser.parse_args()

    if args.queryfile:
        sys.exit("queryfile not supported in this utility")

    if args.prefix:
        output_filename = '%s-usbstor.csv' % args.prefix
    else:
        output_filename = 'usbstor.csv'

    if args.profile:
        cb = CbEnterpriseResponseAPI(profile=args.profile)
    else:
        cb = CbEnterpriseResponseAPI()

    output_file = open(output_filename, 'w')
    writer = csv.writer(output_file, quoting=csv.QUOTE_ALL)

    header_row = ['endpoint', 'vendor', 'product', 'version', 'serial']
    if args.timestamps == True:
        header_row.insert(0, 'timestamp')
    writer.writerow(header_row)

    for term in search_terms:
        query = 'process_name:ntoskrnl.exe regmod:%s' % term

        if args.days:
            query += ' last_update:-%dm' % (args.days*1440)
        elif args.minutes:
            query += ' last_update:-%dm' % args.minutes

        results = usbstor_search(cb, query, query_base=args.query, timestamps=args.timestamps)

        for row in results:
            if _python3 == False:
                row = [col.encode('utf8') if isinstance(col, unicode) else col for col in list(row)]
            writer.writerow(row)

    output_file.close()


if __name__ == '__main__':

    sys.exit(main())
